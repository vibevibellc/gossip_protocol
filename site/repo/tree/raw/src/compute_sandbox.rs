use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{
    DirPerms, FilePerms, WasiCtxBuilder,
    p1::{self, WasiP1Ctx},
    p2::pipe::{MemoryInputPipe, MemoryOutputPipe},
};

use crate::compute::{
    ComputeArtifactRef, ComputeArtifactSpec, ComputeJobSpec, ComputeModuleRef, ComputeShardInput,
    ComputeShardOutput, ComputeShardSpec, ComputeWorkload, MAX_COMPUTE_OUTPUT_BYTES,
    MAX_WASI_MODULE_BYTES, MAX_WASI_MODULE_REF_BYTES, decode_hex_limited, execute_compute_shard,
    validate_compute_artifact_path, validate_compute_input_file_path, validate_compute_job_spec,
};
use crate::{
    protocol::StorageMode,
    storage::{StorageBundleManifest, StorageFileEntry},
};

const WASI_WORK_DIR: &str = "/work";
const WASI_OUTPUT_JSON: &str = "out.json";
const MODULE_FETCH_TIMEOUT_SECS: u64 = 20;

struct SandboxState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

struct EpochDeadlineGuard {
    done: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for EpochDeadlineGuard {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub async fn execute_compute_shard_isolated(
    spec: &ComputeJobSpec,
    shard: &ComputeShardSpec,
    tx_hash: &str,
    provider: &str,
    sandbox_root: &Path,
    artifact_root: &Path,
) -> Result<ComputeShardOutput> {
    match spec.workload {
        ComputeWorkload::WasiPreview1 { .. } => {
            validate_compute_job_spec(spec)?;
            let started = Instant::now();
            let module_bytes = match resolve_wasi_module_bytes(&spec.workload).await {
                Ok(module_bytes) => module_bytes,
                Err(error) => {
                    return Ok(failed_shard_output(
                        shard,
                        started,
                        format!("compute module fetch failed: {}", error),
                    ));
                }
            };
            let spec = spec.clone();
            let shard = shard.clone();
            let tx_hash = tx_hash.to_string();
            let provider = provider.to_string();
            let sandbox_root = sandbox_root.to_path_buf();
            let artifact_root = artifact_root.to_path_buf();
            tokio::task::spawn_blocking(move || {
                execute_wasi_shard_sync(
                    &spec,
                    &module_bytes,
                    &shard,
                    &tx_hash,
                    &provider,
                    &sandbox_root,
                    &artifact_root,
                )
            })
            .await
            .map_err(|error| anyhow!("compute sandbox worker failed: {error}"))?
        }
        _ => execute_compute_shard(&spec.workload, shard),
    }
}

async fn resolve_wasi_module_bytes(workload: &ComputeWorkload) -> Result<Vec<u8>> {
    match workload {
        ComputeWorkload::WasiPreview1 {
            module_hex: Some(module_hex),
            module_ref: None,
            ..
        } => {
            let module = decode_hex_limited(module_hex, MAX_WASI_MODULE_BYTES, "wasi module")?;
            validate_wasm_module_bytes(&module, MAX_WASI_MODULE_BYTES)?;
            Ok(module)
        }
        ComputeWorkload::WasiPreview1 {
            module_hex: None,
            module_ref: Some(module_ref),
            ..
        } => fetch_wasi_module_ref(module_ref).await,
        ComputeWorkload::WasiPreview1 { .. } => {
            bail!("wasi workload requires exactly one module source")
        }
        _ => bail!("compute workload is not wasi_preview1"),
    }
}

async fn fetch_wasi_module_ref(module_ref: &ComputeModuleRef) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(MODULE_FETCH_TIMEOUT_SECS))
        .build()?;
    let manifest_url = format!(
        "{}/v1/storage/contracts/{}/manifest",
        module_ref.host_url.trim_end_matches('/'),
        module_ref.contract_id
    );
    let manifest: StorageBundleManifest = client
        .get(manifest_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let file = validate_module_manifest(module_ref, &manifest)?;
    let file_size_bytes = file.size_bytes;
    let module_url = format!(
        "{}/public/{}/{}",
        module_ref.host_url.trim_end_matches('/'),
        module_ref.contract_id,
        module_ref.path
    );
    let bytes = client
        .get(module_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if bytes.len() as u64 != module_ref.size_bytes || bytes.len() as u64 != file_size_bytes {
        bail!("compute module_ref fetched size mismatch");
    }
    if sha256_hex(&bytes) != module_ref.sha256 {
        bail!("compute module_ref fetched sha256 mismatch");
    }
    let module = bytes.to_vec();
    validate_wasm_module_bytes(&module, MAX_WASI_MODULE_REF_BYTES as usize)?;
    Ok(module)
}

fn validate_module_manifest<'a>(
    module_ref: &ComputeModuleRef,
    manifest: &'a StorageBundleManifest,
) -> Result<&'a StorageFileEntry> {
    if manifest.contract_id != module_ref.contract_id {
        bail!("compute module_ref manifest contract_id mismatch");
    }
    if manifest.merkle_root != module_ref.merkle_root {
        bail!("compute module_ref manifest merkle_root mismatch");
    }
    if !matches!(manifest.mode, StorageMode::PublicRaw { .. }) {
        bail!("compute module_ref storage contract must be public_raw");
    }
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == module_ref.path)
        .ok_or_else(|| anyhow!("compute module_ref path is missing from storage manifest"))?;
    if file.size_bytes != module_ref.size_bytes {
        bail!("compute module_ref manifest size mismatch");
    }
    if file.sha256 != module_ref.sha256 {
        bail!("compute module_ref manifest sha256 mismatch");
    }
    Ok(file)
}

fn validate_wasm_module_bytes(module: &[u8], max_bytes: usize) -> Result<()> {
    if module.is_empty() || module.len() > max_bytes {
        bail!("wasi module size is invalid");
    }
    if module.len() < 8 || &module[..4] != b"\0asm" {
        bail!("wasi module is not a WebAssembly binary");
    }
    Ok(())
}

fn failed_shard_output(
    shard: &ComputeShardSpec,
    started: Instant,
    error: String,
) -> ComputeShardOutput {
    ComputeShardOutput {
        shard_id: shard.shard_id.clone(),
        success: false,
        latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        output: None,
        error: Some(error),
        artifacts: Vec::new(),
        stdout_sample: None,
        stderr_sample: None,
    }
}

fn execute_wasi_shard_sync(
    spec: &ComputeJobSpec,
    module_bytes: &[u8],
    shard: &ComputeShardSpec,
    tx_hash: &str,
    provider: &str,
    sandbox_root: &Path,
    artifact_root: &Path,
) -> Result<ComputeShardOutput> {
    let started = Instant::now();
    let scratch_dir = sandbox_root
        .join(tx_hash)
        .join(&shard.shard_id)
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&scratch_dir)
        .with_context(|| format!("failed to create {}", scratch_dir.display()))?;

    let result = run_wasi_shard(
        spec,
        module_bytes,
        shard,
        tx_hash,
        provider,
        &scratch_dir,
        artifact_root,
    );
    let _ = fs::remove_dir_all(&scratch_dir);

    let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    match result {
        Ok(run) => Ok(ComputeShardOutput {
            shard_id: shard.shard_id.clone(),
            success: true,
            latency_ms,
            output: Some(run.output),
            error: None,
            artifacts: run.artifacts,
            stdout_sample: bytes_to_sample(&run.stdout),
            stderr_sample: bytes_to_sample(&run.stderr),
        }),
        Err(run_error) => Ok(ComputeShardOutput {
            shard_id: shard.shard_id.clone(),
            success: false,
            latency_ms,
            output: None,
            error: Some(run_error.message),
            artifacts: run_error.artifacts,
            stdout_sample: bytes_to_sample(&run_error.stdout),
            stderr_sample: bytes_to_sample(&run_error.stderr),
        }),
    }
}

struct WasiRunSuccess {
    output: Value,
    artifacts: Vec<ComputeArtifactRef>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct WasiRunFailure {
    message: String,
    artifacts: Vec<ComputeArtifactRef>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_wasi_shard(
    spec: &ComputeJobSpec,
    module_bytes: &[u8],
    shard: &ComputeShardSpec,
    tx_hash: &str,
    provider: &str,
    scratch_dir: &Path,
    artifact_root: &Path,
) -> std::result::Result<WasiRunSuccess, WasiRunFailure> {
    let (args, env) = match &spec.workload {
        ComputeWorkload::WasiPreview1 { args, env, .. } => (args, env),
        _ => return Err(failure("compute workload is not wasi_preview1")),
    };
    let ComputeShardInput::Wasi { stdin_hex, files } = &shard.input else {
        return Err(failure("compute shard input is not wasi"));
    };

    if let Err(error) = materialize_inputs(stdin_hex.as_deref(), files, scratch_dir) {
        return Err(failure(error.to_string()));
    }

    let stdout = MemoryOutputPipe::new(spec.sandbox.max_stdout_bytes);
    let stderr = MemoryOutputPipe::new(spec.sandbox.max_stderr_bytes);
    let stdout_reader = stdout.clone();
    let stderr_reader = stderr.clone();

    let run_result = run_wasi_module(
        module_bytes,
        args,
        env,
        stdin_hex.as_deref(),
        scratch_dir,
        stdout,
        stderr,
        spec,
    );

    let stdout = stdout_reader.contents().to_vec();
    let stderr = stderr_reader.contents().to_vec();

    if let Err(error) = run_result {
        let artifacts =
            collect_declared_artifacts(spec, shard, tx_hash, provider, scratch_dir, artifact_root)
                .unwrap_or_default();
        return Err(WasiRunFailure {
            message: normalize_sandbox_error(&error),
            artifacts,
            stdout,
            stderr,
        });
    }

    let artifacts = match collect_declared_artifacts(
        spec,
        shard,
        tx_hash,
        provider,
        scratch_dir,
        artifact_root,
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            return Err(WasiRunFailure {
                message: error.to_string(),
                artifacts: Vec::new(),
                stdout,
                stderr,
            });
        }
    };
    let output = match read_wasi_output_json(scratch_dir) {
        Ok(output) => output,
        Err(error) => {
            return Err(WasiRunFailure {
                message: error.to_string(),
                artifacts,
                stdout,
                stderr,
            });
        }
    };
    Ok(WasiRunSuccess {
        output,
        artifacts,
        stdout,
        stderr,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_wasi_module(
    module_bytes: &[u8],
    args: &[String],
    env: &BTreeMap<String, String>,
    stdin_hex: Option<&str>,
    scratch_dir: &Path,
    stdout: MemoryOutputPipe,
    stderr: MemoryOutputPipe,
    spec: &ComputeJobSpec,
) -> Result<()> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_binary(&engine, module_bytes)?;
    let mut linker: Linker<SandboxState> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;

    let stdin = match stdin_hex {
        Some(input) => decode_hex_limited(
            input,
            crate::compute::MAX_WASI_INPUT_FILE_BYTES,
            "wasi stdin",
        )?,
        None => Vec::new(),
    };
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("job.wasm".to_string());
    argv.extend(args.iter().cloned());
    let env = env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();

    let mut wasi = WasiCtxBuilder::new();
    wasi.stdin(MemoryInputPipe::new(stdin))
        .stdout(stdout)
        .stderr(stderr)
        .args(&argv)
        .envs(&env)
        .allow_blocking_current_thread(true);
    wasi.preopened_dir(
        scratch_dir,
        WASI_WORK_DIR,
        DirPerms::all(),
        FilePerms::all(),
    )?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(spec.sandbox.max_memory_bytes as usize)
        .instances(1)
        .tables(4)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        &engine,
        SandboxState {
            wasi: wasi.build_p1(),
            limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store.set_fuel(spec.sandbox.max_fuel)?;
    store.set_epoch_deadline(1);
    store.epoch_deadline_trap();

    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let _epoch_deadline = start_epoch_deadline(engine.clone(), spec.max_runtime_secs);
    start.call(&mut store, ())?;
    Ok(())
}

fn start_epoch_deadline(engine: Engine, max_runtime_secs: u64) -> EpochDeadlineGuard {
    let (done_tx, done_rx) = mpsc::channel();
    let timeout = Duration::from_secs(max_runtime_secs);
    let handle = thread::spawn(move || {
        if done_rx.recv_timeout(timeout).is_err() {
            engine.increment_epoch();
        }
    });
    EpochDeadlineGuard {
        done: Some(done_tx),
        handle: Some(handle),
    }
}

fn materialize_inputs(
    _stdin_hex: Option<&str>,
    files: &BTreeMap<String, String>,
    scratch_dir: &Path,
) -> Result<()> {
    for (path, contents_hex) in files {
        validate_compute_input_file_path(path)?;
        let bytes = decode_hex_limited(
            contents_hex,
            crate::compute::MAX_WASI_INPUT_FILE_BYTES,
            "wasi input file",
        )?;
        write_sandbox_file(&scratch_dir.join(path), &bytes)?;
    }
    fs::create_dir_all(scratch_dir.join("artifacts"))?;
    Ok(())
}

fn read_wasi_output_json(scratch_dir: &Path) -> Result<Value> {
    let path = scratch_dir.join(WASI_OUTPUT_JSON);
    if !path.exists() {
        return Ok(json!({ "ok": true }));
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() {
        bail!("wasi out.json is not a regular file");
    }
    if metadata.len() as usize > MAX_COMPUTE_OUTPUT_BYTES {
        bail!("wasi out.json exceeds maximum size");
    }
    let bytes = fs::read(&path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

fn collect_declared_artifacts(
    spec: &ComputeJobSpec,
    shard: &ComputeShardSpec,
    tx_hash: &str,
    provider: &str,
    scratch_dir: &Path,
    artifact_root: &Path,
) -> Result<Vec<ComputeArtifactRef>> {
    let mut artifacts = Vec::new();
    let mut total = 0u64;
    for artifact in &spec.artifact_policy.outputs {
        validate_compute_artifact_path(&artifact.path)?;
        let source = scratch_dir.join(&artifact.path);
        if !source.exists() {
            if artifact.required {
                bail!(
                    "required compute artifact {} was not created",
                    artifact.path
                );
            }
            continue;
        }
        let metadata = fs::symlink_metadata(&source)?;
        if !metadata.is_file() {
            bail!("compute artifact {} is not a regular file", artifact.path);
        }
        let size = metadata.len();
        let max_bytes = artifact
            .max_bytes
            .unwrap_or(spec.artifact_policy.max_total_bytes);
        if size > max_bytes {
            bail!(
                "compute artifact {} exceeds its declared size",
                artifact.path
            );
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("compute artifact total size overflow"))?;
        if total > spec.artifact_policy.max_total_bytes {
            bail!("compute artifacts exceed max_total_bytes");
        }
        let bytes = fs::read(&source)?;
        let sha256 = sha256_hex(&bytes);
        let archive_path = artifact_root
            .join(tx_hash)
            .join(&shard.shard_id)
            .join(&artifact.path);
        write_sandbox_file(&archive_path, &bytes)?;
        artifacts.push(artifact_ref(
            artifact,
            tx_hash,
            &shard.shard_id,
            provider,
            size,
            sha256,
        ));
    }
    Ok(artifacts)
}

fn artifact_ref(
    artifact: &ComputeArtifactSpec,
    tx_hash: &str,
    shard_id: &str,
    provider: &str,
    size_bytes: u64,
    sha256: String,
) -> ComputeArtifactRef {
    ComputeArtifactRef {
        path: artifact.path.clone(),
        uri: format!(
            "artifact://compute-jobs/{}/{}/{}",
            tx_hash, shard_id, artifact.path
        ),
        provider: provider.to_string(),
        size_bytes,
        sha256,
        content_type: artifact.content_type.clone(),
    }
}

fn write_sandbox_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("sandbox path is missing a parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn bytes_to_sample(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn failure(message: impl Into<String>) -> WasiRunFailure {
    WasiRunFailure {
        message: message.into(),
        artifacts: Vec::new(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

fn normalize_sandbox_error(error: &anyhow::Error) -> String {
    let message = error.to_string();
    let detail = format!("{error:?}");
    if detail.contains("all fuel consumed") {
        "compute sandbox exhausted fuel".to_string()
    } else if detail.contains("interrupt") || detail.contains("epoch") {
        "compute sandbox exceeded runtime limit".to_string()
    } else if detail.contains("write beyond capacity of MemoryOutputPipe") {
        "compute sandbox exceeded stdio limit".to_string()
    } else if detail.contains("wasm trap") {
        "compute sandbox trapped".to_string()
    } else {
        message
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn compute_artifact_path(
    artifact_root: &Path,
    tx_hash: &str,
    shard_id: &str,
    artifact_path: &str,
) -> Result<PathBuf> {
    validate_compute_artifact_path(artifact_path)?;
    Ok(artifact_root
        .join(tx_hash)
        .join(shard_id)
        .join(artifact_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::{
        ComputeArtifactPolicy, ComputeArtifactSpec, ComputeReducer, ComputeSandboxPolicy,
        default_compute_replication,
    };

    #[tokio::test]
    async fn wasi_sandbox_runs_without_host_preopens() {
        let module = wat::parse_str(r#"(module (func (export "_start")))"#).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let spec = ComputeJobSpec {
            request_id: "wasi-smoke".into(),
            workload: ComputeWorkload::WasiPreview1 {
                module_hex: Some(hex::encode(module)),
                module_ref: None,
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            shards: vec![ComputeShardSpec {
                shard_id: "s0".into(),
                input: ComputeShardInput::Wasi {
                    stdin_hex: None,
                    files: BTreeMap::new(),
                },
            }],
            reducer: ComputeReducer::ShardOutputs,
            max_runtime_secs: 5,
            replication: default_compute_replication(),
            sandbox: ComputeSandboxPolicy {
                max_memory_bytes: crate::compute::MIN_COMPUTE_MEMORY_BYTES,
                max_fuel: 10_000,
                max_stdout_bytes: 256,
                max_stderr_bytes: 256,
                allow_network: false,
            },
            artifact_policy: ComputeArtifactPolicy {
                outputs: Vec::new(),
                max_total_bytes: 0,
            },
        };
        let output = execute_compute_shard_isolated(
            &spec,
            &spec.shards[0],
            "tx",
            "provider",
            &temp.path().join("scratch"),
            &temp.path().join("artifacts"),
        )
        .await
        .unwrap();
        assert!(output.success);
        assert_eq!(output.output, Some(json!({ "ok": true })));
    }

    #[tokio::test]
    async fn wasi_sandbox_enforces_runtime_deadline() {
        let module = wat::parse_str(
            r#"
            (module
              (func (export "_start")
                (loop
                  br 0)))
            "#,
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let spec = ComputeJobSpec {
            request_id: "wasi-timeout".into(),
            workload: ComputeWorkload::WasiPreview1 {
                module_hex: Some(hex::encode(module)),
                module_ref: None,
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            shards: vec![ComputeShardSpec {
                shard_id: "s0".into(),
                input: ComputeShardInput::Wasi {
                    stdin_hex: None,
                    files: BTreeMap::new(),
                },
            }],
            reducer: ComputeReducer::ShardOutputs,
            max_runtime_secs: 1,
            replication: default_compute_replication(),
            sandbox: ComputeSandboxPolicy {
                max_memory_bytes: crate::compute::MIN_COMPUTE_MEMORY_BYTES,
                max_fuel: crate::compute::MAX_COMPUTE_FUEL,
                max_stdout_bytes: 256,
                max_stderr_bytes: 256,
                allow_network: false,
            },
            artifact_policy: ComputeArtifactPolicy {
                outputs: Vec::new(),
                max_total_bytes: 0,
            },
        };

        let started = Instant::now();
        let output = execute_compute_shard_isolated(
            &spec,
            &spec.shards[0],
            "tx",
            "provider",
            &temp.path().join("scratch"),
            &temp.path().join("artifacts"),
        )
        .await
        .unwrap();

        assert!(!output.success);
        assert_eq!(
            output.error.as_deref(),
            Some("compute sandbox exceeded runtime limit")
        );
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test]
    async fn artifact_policy_archives_only_declared_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let spec = ComputeJobSpec {
            request_id: "wasi-artifact".into(),
            workload: ComputeWorkload::WasiPreview1 {
                module_hex: Some("0061736d01000000".into()),
                module_ref: None,
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            shards: vec![ComputeShardSpec {
                shard_id: "s0".into(),
                input: ComputeShardInput::Wasi {
                    stdin_hex: None,
                    files: BTreeMap::new(),
                },
            }],
            reducer: ComputeReducer::ShardOutputs,
            max_runtime_secs: 5,
            replication: default_compute_replication(),
            sandbox: ComputeSandboxPolicy {
                max_memory_bytes: crate::compute::MIN_COMPUTE_MEMORY_BYTES,
                max_fuel: 1_000_000,
                max_stdout_bytes: 256,
                max_stderr_bytes: 256,
                allow_network: false,
            },
            artifact_policy: ComputeArtifactPolicy {
                outputs: vec![ComputeArtifactSpec {
                    path: "artifacts/model.bin".into(),
                    required: true,
                    max_bytes: Some(1024),
                    content_type: Some("application/octet-stream".into()),
                }],
                max_total_bytes: 1024,
            },
        };
        let artifact_root = temp.path().join("artifacts");
        let scratch_dir = temp.path().join("scratch").join("tx").join("s0");
        std::fs::create_dir_all(scratch_dir.join("artifacts")).unwrap();
        std::fs::write(scratch_dir.join("artifacts/model.bin"), b"model-params").unwrap();
        std::fs::write(scratch_dir.join("out.json"), br#"{"value":7}"#).unwrap();

        let output = read_wasi_output_json(&scratch_dir).unwrap();
        let artifacts = collect_declared_artifacts(
            &spec,
            &spec.shards[0],
            "tx",
            "provider",
            &scratch_dir,
            &artifact_root,
        )
        .unwrap();
        assert_eq!(output, json!({ "value": 7 }));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].size_bytes, 12);
        assert_eq!(
            std::fs::read(
                compute_artifact_path(&artifact_root, "tx", "s0", "artifacts/model.bin").unwrap()
            )
            .unwrap(),
            b"model-params"
        );
    }
}
