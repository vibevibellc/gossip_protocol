use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, HOST},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs, net::TcpListener};
use tracing::info;

use crate::protocol::{
    DEFAULT_STORAGE_CHUNK_SIZE_BYTES, DEFAULT_STORAGE_PROOF_INTERVAL_SECS,
    DEFAULT_STORAGE_PROOF_SAMPLE_COUNT, DomainRouteResponse, MerkleProofNode, MerkleProofSide,
    STATIC_SITE_CRITICAL_PREFIX_TARGET_BYTES, STORAGE_REWARD_PER_QUANTUM_SECOND,
    StaticSiteManifest, StorageCompression, StorageContractId, StorageContractSpec, StorageMode,
    StorageProofSample, storage_challenge_indices, storage_chunk_count,
    validate_storage_contract_spec, validate_storage_proof_sample,
};

const BUNDLE_MANIFEST_FILE: &str = "bundle.json";
const CONTRACT_SPEC_FILE: &str = "contract_spec.json";
const ENCRYPTION_SECRETS_FILE: &str = "client_encryption.json";
const CHUNKS_DIR: &str = "chunks";
const STORAGE_BUNDLE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBundleMode {
    Encrypted,
    PublicRaw,
}

#[derive(Debug, Clone)]
pub struct StorageBundleBuildOptions {
    pub contract_id: StorageContractId,
    pub host: String,
    pub mode: StorageBundleMode,
    pub chunk_size_bytes: u64,
    pub duration_secs: u64,
    pub proof_interval_secs: u64,
    pub proof_sample_count: u16,
    pub reward_rate_per_64mib_second: u64,
    pub index_path: Option<String>,
}

impl StorageBundleBuildOptions {
    pub fn encrypted(contract_id: StorageContractId, host: String) -> Self {
        Self {
            contract_id,
            host,
            mode: StorageBundleMode::Encrypted,
            chunk_size_bytes: DEFAULT_STORAGE_CHUNK_SIZE_BYTES,
            duration_secs: 30 * 24 * 60 * 60,
            proof_interval_secs: DEFAULT_STORAGE_PROOF_INTERVAL_SECS,
            proof_sample_count: DEFAULT_STORAGE_PROOF_SAMPLE_COUNT,
            reward_rate_per_64mib_second: STORAGE_REWARD_PER_QUANTUM_SECOND,
            index_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBundleManifest {
    pub version: u16,
    pub contract_id: StorageContractId,
    pub mode: StorageMode,
    pub chunk_size_bytes: u64,
    pub source_size_bytes: u64,
    pub size_bytes: u64,
    pub merkle_root: String,
    #[serde(default)]
    pub files: Vec<StorageFileEntry>,
    pub chunks: Vec<StorageChunkEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<StorageEncryptionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageFileEntry {
    pub path: String,
    pub offset: u64,
    pub size_bytes: u64,
    pub sha256: String,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageChunkEntry {
    pub index: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageEncryptionInfo {
    pub cipher: String,
    pub nonce_prefix_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageEncryptionSecrets {
    pub cipher: String,
    pub key_hex: String,
    pub nonce_prefix_hex: String,
}

#[derive(Debug, Clone)]
pub struct StorageBundleBuild {
    pub spec: StorageContractSpec,
    pub manifest: StorageBundleManifest,
    pub contract_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub spec_path: PathBuf,
    pub secrets_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct StorageHostConfig {
    pub bind_addr: SocketAddr,
    pub store_dir: PathBuf,
    pub node_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChunkProofResponse {
    pub contract_id: StorageContractId,
    pub bytes_stored: u64,
    pub merkle_root: String,
    pub sample: StorageProofSample,
}

#[derive(Clone)]
struct StorageHostState {
    store_dir: PathBuf,
    node_url: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
struct ChunkEncryption {
    key: [u8; 32],
    nonce_prefix: [u8; 16],
}

struct ChunkWriter {
    chunks_dir: PathBuf,
    chunk_size_bytes: usize,
    encryption: Option<ChunkEncryption>,
    current: Vec<u8>,
    chunks: Vec<StorageChunkEntry>,
    source_size_bytes: u64,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
struct SourceFile {
    disk_path: PathBuf,
    storage_path: String,
}

type HostResult<T> = std::result::Result<T, (StatusCode, String)>;

pub async fn build_storage_bundle(
    input: &Path,
    store_dir: &Path,
    options: StorageBundleBuildOptions,
) -> Result<StorageBundleBuild> {
    validate_contract_id_for_path(&options.contract_id)?;
    if options.chunk_size_bytes == 0 || options.chunk_size_bytes > usize::MAX as u64 {
        bail!("storage chunk size is invalid for this platform");
    }

    let contract_dir = contract_dir(store_dir, &options.contract_id)?;
    let chunks_dir = contract_dir.join(CHUNKS_DIR);
    if fs::try_exists(contract_dir.join(BUNDLE_MANIFEST_FILE)).await? {
        bail!(
            "storage bundle {} already exists in {}",
            options.contract_id,
            contract_dir.display()
        );
    }
    fs::create_dir_all(&chunks_dir)
        .await
        .with_context(|| format!("failed to create {}", chunks_dir.display()))?;

    let source_files = collect_source_files(input)?;
    if source_files.is_empty() {
        bail!("storage bundle input is empty");
    }

    let index_path = options.index_path.clone().unwrap_or_else(|| {
        if source_files.len() == 1 {
            source_files[0].storage_path.clone()
        } else {
            "index.html".to_string()
        }
    });

    let encryption = match options.mode {
        StorageBundleMode::Encrypted => Some(random_chunk_encryption()),
        StorageBundleMode::PublicRaw => None,
    };
    let mut writer = ChunkWriter::new(
        chunks_dir.clone(),
        options.chunk_size_bytes as usize,
        encryption.clone(),
    );
    let mut files = Vec::new();
    let mut critical_prefix_hash = None;
    let mut critical_prefix_bytes = None;

    for source in source_files {
        let bytes = fs::read(&source.disk_path)
            .await
            .with_context(|| format!("failed to read {}", source.disk_path.display()))?;
        let offset = writer.source_size_bytes;
        if options.mode == StorageBundleMode::PublicRaw && source.storage_path == index_path {
            let prefix_len = bytes
                .len()
                .min(STATIC_SITE_CRITICAL_PREFIX_TARGET_BYTES as usize);
            if prefix_len > 0 {
                critical_prefix_hash = Some(sha256_hex(&bytes[..prefix_len]));
                critical_prefix_bytes = Some(prefix_len as u32);
            }
        }
        writer.push(&bytes).await?;
        files.push(StorageFileEntry {
            path: source.storage_path.clone(),
            offset,
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            content_type: content_type_for_path(&source.storage_path).to_string(),
        });
    }

    let chunks = writer.finish().await?;
    let source_size_bytes = writer.source_size_bytes;
    let size_bytes = writer.size_bytes;
    if chunks.is_empty() || size_bytes == 0 {
        bail!("storage bundle input produced no chunks");
    }
    let chunk_hashes = chunks
        .iter()
        .map(|chunk| chunk.sha256.clone())
        .collect::<Vec<_>>();
    let merkle_root = merkle_root_from_chunk_hashes(&chunk_hashes)?;

    let mode = match options.mode {
        StorageBundleMode::Encrypted => StorageMode::Encrypted,
        StorageBundleMode::PublicRaw => StorageMode::PublicRaw {
            manifest: Some(StaticSiteManifest {
                index_path,
                critical_prefix_hash,
                critical_prefix_bytes,
                compression: StorageCompression::Identity,
                content_types: files
                    .iter()
                    .map(|file| (file.path.clone(), file.content_type.clone()))
                    .collect::<BTreeMap<_, _>>(),
            }),
        },
    };
    let encryption_info = encryption.as_ref().map(|value| StorageEncryptionInfo {
        cipher: "xchacha20poly1305".to_string(),
        nonce_prefix_hex: hex::encode(value.nonce_prefix),
    });

    let spec = StorageContractSpec {
        contract_id: options.contract_id.clone(),
        host: options.host,
        mode: mode.clone(),
        size_bytes,
        chunk_size_bytes: options.chunk_size_bytes,
        merkle_root: merkle_root.clone(),
        duration_secs: options.duration_secs,
        proof_interval_secs: options.proof_interval_secs,
        proof_sample_count: options.proof_sample_count,
        reward_rate_per_64mib_second: options.reward_rate_per_64mib_second,
    };
    validate_storage_contract_spec(&spec)?;

    let manifest = StorageBundleManifest {
        version: STORAGE_BUNDLE_VERSION,
        contract_id: options.contract_id.clone(),
        mode,
        chunk_size_bytes: options.chunk_size_bytes,
        source_size_bytes,
        size_bytes,
        merkle_root,
        files,
        chunks,
        encryption: encryption_info,
    };

    let manifest_path = contract_dir.join(BUNDLE_MANIFEST_FILE);
    let spec_path = contract_dir.join(CONTRACT_SPEC_FILE);
    write_json_file(&manifest_path, &manifest).await?;
    write_json_file(&spec_path, &spec).await?;

    let secrets_path = if let Some(encryption) = encryption {
        let secrets = StorageEncryptionSecrets {
            cipher: "xchacha20poly1305".to_string(),
            key_hex: hex::encode(encryption.key),
            nonce_prefix_hex: hex::encode(encryption.nonce_prefix),
        };
        let path = contract_dir.join(ENCRYPTION_SECRETS_FILE);
        write_json_file(&path, &secrets).await?;
        Some(path)
    } else {
        None
    };

    Ok(StorageBundleBuild {
        spec,
        manifest,
        contract_dir,
        manifest_path,
        spec_path,
        secrets_path,
    })
}

pub async fn run_storage_host(config: StorageHostConfig) -> Result<()> {
    let state = Arc::new(StorageHostState {
        store_dir: config.store_dir,
        node_url: config.node_url,
        http_client: reqwest::Client::new(),
    });
    let app = Router::new()
        .route(
            "/v1/storage/contracts/:contract_id/manifest",
            get(get_storage_manifest),
        )
        .route(
            "/v1/storage/contracts/:contract_id/chunks/:chunk_index",
            get(get_storage_chunk),
        )
        .route(
            "/v1/storage/contracts/:contract_id/proofs/:chunk_index",
            get(get_storage_chunk_proof),
        )
        .route("/public/:contract_id", get(get_public_index))
        .route("/public/:contract_id/", get(get_public_index))
        .route("/public/:contract_id/*path", get(get_public_file))
        .fallback(get(get_domain_gateway_file))
        .with_state(state);

    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(bind = %config.bind_addr, "storage host listening");
    axum::serve(listener, app).await?;
    Ok(())
}

pub async fn load_bundle_manifest(
    store_dir: &Path,
    contract_id: &str,
) -> Result<StorageBundleManifest> {
    let path = manifest_path(store_dir, contract_id)?;
    let contents = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: StorageBundleManifest = serde_json::from_str(&contents)?;
    Ok(manifest)
}

pub async fn storage_sample_from_store(
    store_dir: &Path,
    contract_id: &str,
    chunk_index: u64,
) -> Result<StorageProofSample> {
    let manifest = load_bundle_manifest(store_dir, contract_id).await?;
    storage_sample_from_manifest(store_dir, &manifest, chunk_index).await
}

pub async fn storage_sample_from_manifest(
    store_dir: &Path,
    manifest: &StorageBundleManifest,
    chunk_index: u64,
) -> Result<StorageProofSample> {
    let chunk = manifest
        .chunks
        .get(chunk_index as usize)
        .ok_or_else(|| anyhow!("unknown storage chunk index {chunk_index}"))?;
    if chunk.index != chunk_index {
        bail!("storage manifest chunk index mismatch");
    }
    let bytes = read_chunk_bytes(store_dir, &manifest.contract_id, chunk_index).await?;
    let actual_hash = sha256_hex(&bytes);
    if actual_hash != chunk.sha256 {
        bail!("storage chunk hash mismatch for index {chunk_index}");
    }
    let hashes = manifest
        .chunks
        .iter()
        .map(|entry| entry.sha256.clone())
        .collect::<Vec<_>>();
    let proof = merkle_proof_from_chunk_hashes(&hashes, chunk_index)?;
    let sample = StorageProofSample {
        chunk_index,
        chunk_hash: chunk.sha256.clone(),
        proof,
    };
    validate_storage_proof_sample(&sample, &manifest.merkle_root)?;
    Ok(sample)
}

pub async fn fetch_storage_proof_samples(
    host_url: &str,
    spec: &StorageContractSpec,
    challenge_seed: &str,
) -> Result<Vec<StorageProofSample>> {
    let indices = storage_challenge_indices(
        challenge_seed,
        storage_chunk_count(spec),
        spec.proof_sample_count,
    )?;
    let client = reqwest::Client::new();
    let mut samples = Vec::with_capacity(indices.len());
    for index in indices {
        let url = format!(
            "{}/v1/storage/contracts/{}/proofs/{}",
            host_url.trim_end_matches('/'),
            spec.contract_id,
            index
        );
        let response = client.get(url).send().await?.error_for_status()?;
        let proof: StorageChunkProofResponse = response.json().await?;
        if proof.contract_id != spec.contract_id {
            bail!("storage host returned a proof for the wrong contract");
        }
        if proof.bytes_stored < spec.size_bytes {
            bail!("storage host proof covers fewer bytes than the contract requires");
        }
        if proof.merkle_root != spec.merkle_root {
            bail!("storage host proof merkle_root mismatch");
        }
        if proof.sample.chunk_index != index {
            bail!("storage host returned the wrong challenged chunk");
        }
        validate_storage_proof_sample(&proof.sample, &spec.merkle_root)?;
        samples.push(proof.sample);
    }
    Ok(samples)
}

pub fn merkle_root_from_chunk_hashes(hashes: &[String]) -> Result<String> {
    let layers = merkle_layers(hashes)?;
    let root = layers
        .last()
        .and_then(|layer| layer.first())
        .ok_or_else(|| anyhow!("storage merkle tree requires at least one chunk"))?;
    Ok(hex::encode(root))
}

pub fn merkle_proof_from_chunk_hashes(
    hashes: &[String],
    chunk_index: u64,
) -> Result<Vec<MerkleProofNode>> {
    let layers = merkle_layers(hashes)?;
    let mut index = usize::try_from(chunk_index).map_err(|_| anyhow!("chunk index too large"))?;
    if index >= hashes.len() {
        bail!("chunk index is outside the merkle tree");
    }

    let mut proof = Vec::new();
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        let is_right = index % 2 == 1;
        let sibling_index = if is_right { index - 1 } else { index + 1 };
        if let Some(sibling) = layer.get(sibling_index) {
            proof.push(MerkleProofNode {
                side: if is_right {
                    MerkleProofSide::Left
                } else {
                    MerkleProofSide::Right
                },
                hash: hex::encode(sibling),
            });
        }
        index /= 2;
    }
    Ok(proof)
}

pub fn contract_dir(store_dir: &Path, contract_id: &str) -> Result<PathBuf> {
    validate_contract_id_for_path(contract_id)?;
    Ok(store_dir.join("contracts").join(contract_id))
}

fn manifest_path(store_dir: &Path, contract_id: &str) -> Result<PathBuf> {
    Ok(contract_dir(store_dir, contract_id)?.join(BUNDLE_MANIFEST_FILE))
}

fn chunk_path(store_dir: &Path, contract_id: &str, chunk_index: u64) -> Result<PathBuf> {
    Ok(contract_dir(store_dir, contract_id)?
        .join(CHUNKS_DIR)
        .join(format!("{chunk_index:020}.chunk")))
}

async fn get_storage_manifest(
    State(state): State<Arc<StorageHostState>>,
    AxumPath(contract_id): AxumPath<String>,
) -> HostResult<Json<StorageBundleManifest>> {
    load_bundle_manifest(&state.store_dir, &contract_id)
        .await
        .map(Json)
        .map_err(host_error)
}

async fn get_storage_chunk(
    State(state): State<Arc<StorageHostState>>,
    AxumPath((contract_id, chunk_index)): AxumPath<(String, u64)>,
) -> HostResult<Response> {
    let bytes = read_chunk_bytes(&state.store_dir, &contract_id, chunk_index)
        .await
        .map_err(host_error)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((headers, bytes).into_response())
}

async fn get_storage_chunk_proof(
    State(state): State<Arc<StorageHostState>>,
    AxumPath((contract_id, chunk_index)): AxumPath<(String, u64)>,
) -> HostResult<Json<StorageChunkProofResponse>> {
    let manifest = load_bundle_manifest(&state.store_dir, &contract_id)
        .await
        .map_err(host_error)?;
    let sample = storage_sample_from_manifest(&state.store_dir, &manifest, chunk_index)
        .await
        .map_err(host_error)?;
    Ok(Json(StorageChunkProofResponse {
        contract_id,
        bytes_stored: manifest.size_bytes,
        merkle_root: manifest.merkle_root,
        sample,
    }))
}

async fn get_public_index(
    State(state): State<Arc<StorageHostState>>,
    AxumPath(contract_id): AxumPath<String>,
) -> HostResult<Response> {
    public_file_response(&state.store_dir, &contract_id, "").await
}

async fn get_public_file(
    State(state): State<Arc<StorageHostState>>,
    AxumPath((contract_id, path)): AxumPath<(String, String)>,
) -> HostResult<Response> {
    public_file_response(&state.store_dir, &contract_id, &path).await
}

async fn get_domain_gateway_file(
    State(state): State<Arc<StorageHostState>>,
    headers: HeaderMap,
    uri: Uri,
) -> HostResult<Response> {
    let host = route_host_from_headers(&headers).map_err(host_error)?;
    let route = fetch_domain_route(&state, &host)
        .await
        .map_err(host_error)?;
    if uri.path() == "/.well-known/gossip-protocol-route" {
        let mut response = Json(serde_json::json!({
            "chain_id": route.chain_id,
            "lease_id": route.lease.lease_id,
            "fqdn": route.lease.fqdn,
            "contract_id": route.contract.contract_id,
            "merkle_root": route.contract.spec.merkle_root,
        }))
        .into_response();
        apply_domain_gateway_headers(response.headers_mut(), "application/json; charset=utf-8");
        return Ok(response);
    }

    let request_path = uri.path().trim_start_matches('/');
    let (bytes, content_type) = read_public_file_bytes(
        &state.store_dir,
        &route.lease.target_contract_id,
        request_path,
    )
    .await
    .map_err(host_error)?;
    let mut response = Body::from(bytes).into_response();
    apply_domain_gateway_headers(response.headers_mut(), &content_type);
    Ok(response)
}

async fn public_file_response(
    store_dir: &Path,
    contract_id: &str,
    request_path: &str,
) -> HostResult<Response> {
    let (bytes, content_type) = read_public_file_bytes(store_dir, contract_id, request_path)
        .await
        .map_err(host_error)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    Ok((headers, Body::from(bytes)).into_response())
}

async fn read_public_file_bytes(
    store_dir: &Path,
    contract_id: &str,
    request_path: &str,
) -> Result<(Vec<u8>, String)> {
    let manifest = load_bundle_manifest(store_dir, contract_id).await?;
    let public_manifest = match &manifest.mode {
        StorageMode::PublicRaw { manifest } => manifest
            .as_ref()
            .ok_or_else(|| anyhow!("public storage bundle is missing its static manifest"))?,
        StorageMode::Encrypted => bail!("encrypted storage bundles cannot be served publicly"),
    };
    let request_path = normalize_public_request_path(request_path)?;
    let target_path = if request_path.is_empty() {
        public_manifest.index_path.as_str()
    } else {
        request_path.as_str()
    };
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == target_path)
        .or_else(|| {
            if request_path.contains('.') {
                None
            } else {
                manifest
                    .files
                    .iter()
                    .find(|file| file.path == public_manifest.index_path)
            }
        })
        .ok_or_else(|| anyhow!("public file not found"))?;

    let mut remaining = file.size_bytes as usize;
    let mut offset = file.offset;
    let mut out = Vec::with_capacity(remaining);
    while remaining > 0 {
        let chunk_index = offset / manifest.chunk_size_bytes;
        let chunk_offset = (offset % manifest.chunk_size_bytes) as usize;
        let chunk = read_chunk_bytes(store_dir, &manifest.contract_id, chunk_index).await?;
        if chunk_offset >= chunk.len() {
            bail!("public file offset is outside chunk bounds");
        }
        let take = remaining.min(chunk.len() - chunk_offset);
        out.extend_from_slice(&chunk[chunk_offset..chunk_offset + take]);
        remaining -= take;
        offset += take as u64;
    }
    if sha256_hex(&out) != file.sha256 {
        bail!("public file hash mismatch");
    }
    Ok((out, file.content_type.clone()))
}

async fn fetch_domain_route(state: &StorageHostState, host: &str) -> Result<DomainRouteResponse> {
    let node_url = state
        .node_url
        .as_deref()
        .ok_or_else(|| anyhow!("storage host is not configured with --node for domain routing"))?;
    let url = format!(
        "{}/v1/control/domain-route/{}",
        node_url.trim_end_matches('/'),
        host
    );
    let response = state
        .http_client
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json().await?)
}

fn route_host_from_headers(headers: &HeaderMap) -> Result<String> {
    let host = headers
        .get(HOST)
        .ok_or_else(|| anyhow!("domain gateway request is missing Host header"))?
        .to_str()
        .context("domain gateway Host header is invalid")?;
    let host = host
        .trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains('\\') {
        bail!("domain gateway Host header is invalid");
    }
    Ok(host)
}

fn apply_domain_gateway_headers(headers: &mut HeaderMap, content_type: &str) {
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "sandbox allow-scripts allow-forms allow-popups allow-downloads allow-top-navigation-by-user-activation",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), camera=(), microphone=(), payment=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("cross-origin"),
    );
}

async fn read_chunk_bytes(
    store_dir: &Path,
    contract_id: &str,
    chunk_index: u64,
) -> Result<Vec<u8>> {
    let path = chunk_path(store_dir, contract_id, chunk_index)?;
    fs::read(&path)
        .await
        .with_context(|| format!("failed to read storage chunk {}", path.display()))
}

impl ChunkWriter {
    fn new(
        chunks_dir: PathBuf,
        chunk_size_bytes: usize,
        encryption: Option<ChunkEncryption>,
    ) -> Self {
        Self {
            chunks_dir,
            chunk_size_bytes,
            encryption,
            current: Vec::with_capacity(chunk_size_bytes),
            chunks: Vec::new(),
            source_size_bytes: 0,
            size_bytes: 0,
        }
    }

    async fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.source_size_bytes += bytes.len() as u64;
        while !bytes.is_empty() {
            let remaining_in_chunk = self.chunk_size_bytes - self.current.len();
            let take = remaining_in_chunk.min(bytes.len());
            self.current.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.current.len() == self.chunk_size_bytes {
                self.flush_current().await?;
            }
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<Vec<StorageChunkEntry>> {
        if !self.current.is_empty() {
            self.flush_current().await?;
        }
        Ok(self.chunks.clone())
    }

    async fn flush_current(&mut self) -> Result<()> {
        let index = self.chunks.len() as u64;
        let plain = std::mem::take(&mut self.current);
        let chunk = if let Some(encryption) = &self.encryption {
            encryption.encrypt_chunk(index, &plain)?
        } else {
            plain
        };
        let path = self.chunks_dir.join(format!("{index:020}.chunk"));
        fs::write(&path, &chunk)
            .await
            .with_context(|| format!("failed to write {}", path.display()))?;
        let sha256 = sha256_hex(&chunk);
        self.size_bytes += chunk.len() as u64;
        self.chunks.push(StorageChunkEntry {
            index,
            size_bytes: chunk.len() as u64,
            sha256,
        });
        self.current = Vec::with_capacity(self.chunk_size_bytes);
        Ok(())
    }
}

impl ChunkEncryption {
    fn encrypt_chunk(&self, index: u64, bytes: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| anyhow!("invalid storage encryption key length"))?;
        cipher
            .encrypt(XNonce::from_slice(&self.nonce(index)), bytes)
            .map_err(|_| anyhow!("failed to encrypt storage chunk"))
    }

    fn nonce(&self, index: u64) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.nonce_prefix);
        nonce[16..].copy_from_slice(&index.to_be_bytes());
        nonce
    }
}

fn random_chunk_encryption() -> ChunkEncryption {
    let mut rng = thread_rng();
    let mut key = [0u8; 32];
    let mut nonce_prefix = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce_prefix);
    ChunkEncryption { key, nonce_prefix }
}

fn collect_source_files(input: &Path) -> Result<Vec<SourceFile>> {
    let metadata = std::fs::metadata(input)
        .with_context(|| format!("failed to inspect storage input {}", input.display()))?;
    if metadata.is_file() {
        let file_name = input
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("storage input file name must be valid UTF-8"))?;
        return Ok(vec![SourceFile {
            disk_path: input.to_path_buf(),
            storage_path: file_name.to_string(),
        }]);
    }
    if !metadata.is_dir() {
        bail!("storage input must be a file or directory");
    }

    let mut stack = vec![input.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed to read directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(SourceFile {
                    storage_path: storage_relative_path(input, &path)?,
                    disk_path: path,
                });
            }
        }
    }
    files.sort_by(|left, right| left.storage_path.cmp(&right.storage_path));
    Ok(files)
}

fn storage_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| anyhow!("storage paths must be valid UTF-8"))?;
                if part.is_empty() || part == "." || part == ".." {
                    bail!("storage path component is invalid");
                }
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            _ => bail!("storage paths may not contain parent or absolute components"),
        }
    }
    if parts.is_empty() {
        bail!("storage path is empty");
    }
    Ok(parts.join("/"))
}

fn normalize_public_request_path(path: &str) -> Result<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.contains("..") || trimmed.contains('\\') {
        bail!("public storage path is invalid");
    }
    Ok(trimmed.to_string())
}

fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "webmanifest" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn merkle_layers(hashes: &[String]) -> Result<Vec<Vec<[u8; 32]>>> {
    if hashes.is_empty() {
        bail!("storage merkle tree requires at least one chunk");
    }
    let mut layers = vec![
        hashes
            .iter()
            .map(|hash| decode_sha256_hex(hash))
            .collect::<Result<Vec<_>>>()?,
    ];
    while layers.last().map(Vec::len).unwrap_or(0) > 1 {
        let previous = layers.last().unwrap();
        let mut next = Vec::with_capacity(previous.len().div_ceil(2));
        for pair in previous.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                next.push(hasher.finalize().into());
            }
        }
        layers.push(next);
    }
    Ok(layers)
}

fn decode_sha256_hex(input: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(input).context("invalid sha256 hex")?;
    if bytes.len() != 32 {
        bail!("sha256 hex must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

fn validate_contract_id_for_path(contract_id: &str) -> Result<()> {
    if contract_id.trim().is_empty()
        || contract_id.contains('/')
        || contract_id.contains('\\')
        || contract_id.contains("..")
    {
        bail!("storage contract_id is not safe for a local storage path");
    }
    Ok(())
}

fn host_error(error: anyhow::Error) -> (StatusCode, String) {
    let message = error.to_string();
    let status = if message.contains("not found")
        || message.contains("unknown storage chunk")
        || message.contains("failed to read storage chunk")
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{StorageMode, validate_storage_proof_sample};

    #[test]
    fn merkle_proof_validates_for_odd_chunk_count() {
        let hashes = vec![sha256_hex(b"one"), sha256_hex(b"two"), sha256_hex(b"three")];
        let root = merkle_root_from_chunk_hashes(&hashes).unwrap();
        let proof = merkle_proof_from_chunk_hashes(&hashes, 2).unwrap();
        let sample = StorageProofSample {
            chunk_index: 2,
            chunk_hash: hashes[2].clone(),
            proof,
        };
        validate_storage_proof_sample(&sample, &root).unwrap();
    }

    #[tokio::test]
    async fn public_bundle_writes_manifest_and_proof_samples() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("site");
        fs::create_dir_all(&input).await.unwrap();
        fs::write(input.join("index.html"), "<!doctype html><h1>ok</h1>")
            .await
            .unwrap();
        fs::write(input.join("app.css"), "body{color:#111}")
            .await
            .unwrap();

        let options = StorageBundleBuildOptions {
            contract_id: "site-contract".to_string(),
            host: "host-address".to_string(),
            mode: StorageBundleMode::PublicRaw,
            chunk_size_bytes: 1024,
            duration_secs: 60,
            proof_interval_secs: 10,
            proof_sample_count: 1,
            reward_rate_per_64mib_second: STORAGE_REWARD_PER_QUANTUM_SECOND,
            index_path: Some("index.html".to_string()),
        };
        let build = build_storage_bundle(&input, temp.path(), options)
            .await
            .unwrap();
        assert!(matches!(build.spec.mode, StorageMode::PublicRaw { .. }));
        assert_eq!(
            build.manifest.chunks.len(),
            storage_chunk_count(&build.spec) as usize
        );

        let sample = storage_sample_from_store(temp.path(), "site-contract", 0)
            .await
            .unwrap();
        validate_storage_proof_sample(&sample, &build.spec.merkle_root).unwrap();

        let (bytes, content_type) = read_public_file_bytes(temp.path(), "site-contract", "")
            .await
            .unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("<h1>ok</h1>"));
        assert_eq!(content_type, "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn encrypted_bundle_keeps_key_out_of_host_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("payload.txt");
        fs::write(&input, "secret payload").await.unwrap();
        let options = StorageBundleBuildOptions {
            contract_id: "encrypted-contract".to_string(),
            host: "host-address".to_string(),
            mode: StorageBundleMode::Encrypted,
            chunk_size_bytes: 1024,
            duration_secs: 60,
            proof_interval_secs: 10,
            proof_sample_count: 1,
            reward_rate_per_64mib_second: STORAGE_REWARD_PER_QUANTUM_SECOND,
            index_path: None,
        };
        let build = build_storage_bundle(&input, temp.path(), options)
            .await
            .unwrap();
        assert!(matches!(build.spec.mode, StorageMode::Encrypted));
        assert!(build.manifest.encryption.is_some());
        assert!(build.secrets_path.is_some());
        let manifest_json = fs::read_to_string(build.manifest_path).await.unwrap();
        assert!(!manifest_json.contains("key_hex"));
    }
}
