use std::{collections::BTreeMap, time::Instant};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::protocol::{
    Address, MAX_STORAGE_CONTRACT_ID_BYTES, MAX_STORAGE_MANIFEST_PATH_BYTES, MICRO_CT,
    StorageContractId, TxHash, compute_hash,
};

pub const COMPUTE_JOB_BASE_COST: u64 = MICRO_CT;
pub const COMPUTE_SHARD_BASE_COST: u64 = MICRO_CT / 10;
pub const COMPUTE_RUNTIME_SURCHARGE_STEP_SECS: u64 = 60;
pub const COMPUTE_RUNTIME_SURCHARGE_STEP_COST: u64 = MICRO_CT / 4;
pub const MIN_COMPUTE_RUNTIME_SECS: u64 = 1;
pub const MAX_COMPUTE_RUNTIME_SECS: u64 = 3_600;
pub const MAX_COMPUTE_REQUEST_ID_BYTES: usize = 128;
pub const MAX_COMPUTE_SHARDS: usize = 256;
pub const MAX_COMPUTE_SHARD_ID_BYTES: usize = 128;
pub const MAX_COMPUTE_INTEGERS_PER_SHARD: usize = 8_192;
pub const MAX_COMPUTE_INTEGER_ABS: i64 = 1_000_000;
pub const MAX_MONTE_CARLO_SAMPLES_PER_SHARD: u64 = 10_000_000;
pub const MAX_COMPUTE_OUTPUT_BYTES: usize = 16_384;
pub const MAX_COMPUTE_REPLICATION: u16 = 8;
pub const MAX_WASI_MODULE_BYTES: usize = 64 * 1024;
pub const MAX_WASI_MODULE_REF_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_WASI_MODULE_HOST_URL_BYTES: usize = 512;
pub const MAX_WASI_ARGS: usize = 16;
pub const MAX_WASI_ARG_BYTES: usize = 256;
pub const MAX_WASI_ENV_VARS: usize = 16;
pub const MAX_WASI_ENV_KEY_BYTES: usize = 64;
pub const MAX_WASI_ENV_VALUE_BYTES: usize = 512;
pub const MAX_WASI_INPUT_FILES: usize = 16;
pub const MAX_WASI_INPUT_FILE_BYTES: usize = 64 * 1024;
pub const MAX_WASI_INPUT_TOTAL_BYTES: usize = 128 * 1024;
pub const MIN_COMPUTE_MEMORY_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_COMPUTE_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_COMPUTE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_COMPUTE_FUEL: u64 = 500_000_000;
pub const MAX_COMPUTE_FUEL: u64 = 20_000_000_000;
pub const DEFAULT_COMPUTE_STDIO_BYTES: usize = 4 * 1024;
pub const MAX_COMPUTE_STDIO_BYTES: usize = 16 * 1024;
pub const MAX_COMPUTE_ARTIFACTS: usize = 16;
pub const MAX_COMPUTE_ARTIFACT_PATH_BYTES: usize = 256;
pub const MAX_COMPUTE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const COMPUTE_WASI_SURCHARGE_COST: u64 = MICRO_CT;
pub const COMPUTE_MODULE_REF_SURCHARGE_PER_MIB: u64 = MICRO_CT / 40;
pub const COMPUTE_ARTIFACT_SURCHARGE_PER_MIB: u64 = MICRO_CT / 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputeIntegerOperation {
    Sum,
    SumSquares,
    Count,
    MinMax,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeModuleRef {
    pub contract_id: StorageContractId,
    pub host_url: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComputeWorkload {
    IntegerMap {
        operation: ComputeIntegerOperation,
    },
    MonteCarloPi,
    WasiPreview1 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        module_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        module_ref: Option<ComputeModuleRef>,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComputeShardInput {
    Integers {
        values: Vec<i64>,
    },
    MonteCarlo {
        samples: u64,
        seed: u64,
    },
    Wasi {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin_hex: Option<String>,
        #[serde(default)]
        files: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeShardSpec {
    pub shard_id: String,
    pub input: ComputeShardInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputeReducer {
    Sum,
    SumSquares,
    Count,
    MinMax,
    MonteCarloPi,
    ShardOutputs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeSandboxPolicy {
    #[serde(default = "default_compute_memory_bytes")]
    pub max_memory_bytes: u64,
    #[serde(default = "default_compute_fuel")]
    pub max_fuel: u64,
    #[serde(default = "default_compute_stdio_bytes")]
    pub max_stdout_bytes: usize,
    #[serde(default = "default_compute_stdio_bytes")]
    pub max_stderr_bytes: usize,
    #[serde(default)]
    pub allow_network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeArtifactSpec {
    pub path: String,
    #[serde(default = "default_required_artifact")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeArtifactPolicy {
    #[serde(default)]
    pub outputs: Vec<ComputeArtifactSpec>,
    #[serde(default)]
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJobSpec {
    pub request_id: String,
    pub workload: ComputeWorkload,
    pub shards: Vec<ComputeShardSpec>,
    pub reducer: ComputeReducer,
    #[serde(default = "default_compute_runtime_secs")]
    pub max_runtime_secs: u64,
    #[serde(default = "default_compute_replication")]
    pub replication: u16,
    #[serde(default = "default_compute_sandbox_policy")]
    pub sandbox: ComputeSandboxPolicy,
    #[serde(default = "default_compute_artifact_policy")]
    pub artifact_policy: ComputeArtifactPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeArtifactRef {
    pub path: String,
    pub uri: String,
    pub provider: Address,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComputeShardOutput {
    pub shard_id: String,
    pub success: bool,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ComputeArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_sample: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_sample: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComputeReceiptBody {
    pub chain_id: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    pub executor: Address,
    pub observed_at: DateTime<Utc>,
    pub job_hash: String,
    #[serde(default)]
    pub assigned_agents: BTreeMap<String, Address>,
    #[serde(default)]
    pub shard_outputs: Vec<ComputeShardOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduced_output: Option<Value>,
    pub latency_ms: u64,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedComputeReceipt {
    pub id: String,
    pub body: ComputeReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComputeShardLeaseBody {
    pub chain_id: String,
    pub lease_id: String,
    pub parent_validator: Address,
    pub agent_public_key: Address,
    pub tx_hash: TxHash,
    pub request_id: String,
    pub job_hash: String,
    pub workload: ComputeWorkload,
    pub reducer: ComputeReducer,
    #[serde(default = "default_compute_runtime_secs")]
    pub max_runtime_secs: u64,
    #[serde(default = "default_compute_sandbox_policy")]
    pub sandbox: ComputeSandboxPolicy,
    #[serde(default = "default_compute_artifact_policy")]
    pub artifact_policy: ComputeArtifactPolicy,
    pub shard: ComputeShardSpec,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedComputeShardLease {
    pub id: String,
    pub body: ComputeShardLeaseBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegatedComputeShardReceiptBody {
    pub chain_id: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    pub agent_public_key: Address,
    pub parent_validator: Address,
    pub lease_id: String,
    pub job_hash: String,
    pub shard_output: ComputeShardOutput,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedDelegatedComputeShardReceipt {
    pub id: String,
    pub body: DelegatedComputeShardReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockComputeBatch {
    pub tx_hash: TxHash,
    pub receipts: Vec<SignedComputeReceipt>,
}

pub fn default_compute_runtime_secs() -> u64 {
    300
}

pub fn default_compute_replication() -> u16 {
    1
}

pub fn default_compute_memory_bytes() -> u64 {
    DEFAULT_COMPUTE_MEMORY_BYTES
}

pub fn default_compute_fuel() -> u64 {
    DEFAULT_COMPUTE_FUEL
}

pub fn default_compute_stdio_bytes() -> usize {
    DEFAULT_COMPUTE_STDIO_BYTES
}

pub fn default_compute_sandbox_policy() -> ComputeSandboxPolicy {
    ComputeSandboxPolicy {
        max_memory_bytes: DEFAULT_COMPUTE_MEMORY_BYTES,
        max_fuel: DEFAULT_COMPUTE_FUEL,
        max_stdout_bytes: DEFAULT_COMPUTE_STDIO_BYTES,
        max_stderr_bytes: DEFAULT_COMPUTE_STDIO_BYTES,
        allow_network: false,
    }
}

pub fn default_compute_artifact_policy() -> ComputeArtifactPolicy {
    ComputeArtifactPolicy {
        outputs: Vec::new(),
        max_total_bytes: 0,
    }
}

pub fn default_required_artifact() -> bool {
    true
}

pub fn compute_job_hash(spec: &ComputeJobSpec) -> Result<String> {
    validate_compute_job_spec(spec)?;
    compute_hash(spec)
}

pub fn compute_job_cost(spec: &ComputeJobSpec) -> Result<u64> {
    compute_job_cost_for_replication(spec, u64::from(spec.replication.max(1)))
}

pub fn compute_job_cost_for_replication(
    spec: &ComputeJobSpec,
    effective_replication: u64,
) -> Result<u64> {
    validate_compute_job_spec(spec)?;
    if effective_replication == 0 || effective_replication > u64::from(MAX_COMPUTE_REPLICATION) {
        bail!("compute effective replication is invalid");
    }
    let mut total = COMPUTE_JOB_BASE_COST;
    total = total
        .checked_add(spec.shards.len() as u64 * COMPUTE_SHARD_BASE_COST)
        .ok_or_else(|| anyhow!("compute job cost overflow"))?;
    if spec.max_runtime_secs > default_compute_runtime_secs() {
        let extra_secs = spec.max_runtime_secs - default_compute_runtime_secs();
        let steps = extra_secs.div_ceil(COMPUTE_RUNTIME_SURCHARGE_STEP_SECS);
        total = total
            .checked_add(steps * COMPUTE_RUNTIME_SURCHARGE_STEP_COST)
            .ok_or_else(|| anyhow!("compute job cost overflow"))?;
    }
    if matches!(spec.workload, ComputeWorkload::WasiPreview1 { .. }) {
        total = total
            .checked_add(COMPUTE_WASI_SURCHARGE_COST)
            .ok_or_else(|| anyhow!("compute job cost overflow"))?;
    }
    if let Some(module_ref) = compute_wasi_module_ref(&spec.workload) {
        let module_mib = module_ref.size_bytes.div_ceil(1024 * 1024);
        total = total
            .checked_add(module_mib * COMPUTE_MODULE_REF_SURCHARGE_PER_MIB)
            .ok_or_else(|| anyhow!("compute job cost overflow"))?;
    }
    if spec.artifact_policy.max_total_bytes > 0 {
        let artifact_mib = spec.artifact_policy.max_total_bytes.div_ceil(1024 * 1024);
        total = total
            .checked_add(artifact_mib * COMPUTE_ARTIFACT_SURCHARGE_PER_MIB)
            .ok_or_else(|| anyhow!("compute job cost overflow"))?;
    }
    total
        .checked_mul(effective_replication)
        .ok_or_else(|| anyhow!("compute job cost overflow"))
}

pub fn validate_compute_job_spec(spec: &ComputeJobSpec) -> Result<()> {
    if spec.request_id.trim().is_empty() || spec.request_id.len() > MAX_COMPUTE_REQUEST_ID_BYTES {
        bail!("compute request_id is invalid");
    }
    if spec.shards.is_empty() || spec.shards.len() > MAX_COMPUTE_SHARDS {
        bail!("compute job must include between 1 and {MAX_COMPUTE_SHARDS} shards");
    }
    if spec.max_runtime_secs < MIN_COMPUTE_RUNTIME_SECS
        || spec.max_runtime_secs > MAX_COMPUTE_RUNTIME_SECS
    {
        bail!(
            "compute max_runtime_secs must be between {MIN_COMPUTE_RUNTIME_SECS} and {MAX_COMPUTE_RUNTIME_SECS}"
        );
    }
    if spec.replication == 0 || spec.replication > MAX_COMPUTE_REPLICATION {
        bail!("compute replication is invalid");
    }

    validate_compute_sandbox_policy(&spec.sandbox)?;
    validate_compute_artifact_policy(&spec.artifact_policy)?;
    validate_compute_workload(&spec.workload)?;
    validate_reducer_matches_workload(&spec.workload, &spec.reducer)?;
    let mut seen = std::collections::BTreeSet::new();
    for shard in &spec.shards {
        validate_compute_shard_spec(&spec.workload, shard)?;
        if !seen.insert(shard.shard_id.clone()) {
            bail!("compute shard_id appears more than once");
        }
    }
    Ok(())
}

pub fn validate_compute_sandbox_policy(policy: &ComputeSandboxPolicy) -> Result<()> {
    if policy.max_memory_bytes < MIN_COMPUTE_MEMORY_BYTES
        || policy.max_memory_bytes > MAX_COMPUTE_MEMORY_BYTES
    {
        bail!("compute sandbox max_memory_bytes is invalid");
    }
    if policy.max_fuel == 0 || policy.max_fuel > MAX_COMPUTE_FUEL {
        bail!("compute sandbox max_fuel is invalid");
    }
    if policy.max_stdout_bytes > MAX_COMPUTE_STDIO_BYTES {
        bail!("compute sandbox max_stdout_bytes is invalid");
    }
    if policy.max_stderr_bytes > MAX_COMPUTE_STDIO_BYTES {
        bail!("compute sandbox max_stderr_bytes is invalid");
    }
    if policy.allow_network {
        bail!("compute sandbox networking is not available for production jobs");
    }
    Ok(())
}

pub fn validate_compute_artifact_policy(policy: &ComputeArtifactPolicy) -> Result<()> {
    if policy.outputs.len() > MAX_COMPUTE_ARTIFACTS {
        bail!("compute artifact policy has too many outputs");
    }
    if policy.max_total_bytes > MAX_COMPUTE_ARTIFACT_BYTES {
        bail!("compute artifact policy max_total_bytes is invalid");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut declared_total = 0u64;
    for artifact in &policy.outputs {
        validate_compute_artifact_path(&artifact.path)?;
        if !seen.insert(artifact.path.clone()) {
            bail!("compute artifact path appears more than once");
        }
        if let Some(max_bytes) = artifact.max_bytes {
            if max_bytes == 0 || max_bytes > MAX_COMPUTE_ARTIFACT_BYTES {
                bail!("compute artifact max_bytes is invalid");
            }
            declared_total = declared_total
                .checked_add(max_bytes)
                .ok_or_else(|| anyhow!("compute artifact byte limit overflow"))?;
        }
        if let Some(content_type) = &artifact.content_type
            && (content_type.trim().is_empty()
                || content_type.len() > crate::protocol::MAX_STORAGE_CONTENT_TYPE_BYTES)
        {
            bail!("compute artifact content_type is invalid");
        }
    }
    if !policy.outputs.is_empty() && policy.max_total_bytes == 0 {
        bail!("compute artifact policy with outputs requires max_total_bytes");
    }
    if policy.max_total_bytes > 0 && declared_total > policy.max_total_bytes {
        bail!("compute artifact max_total_bytes is below declared output limits");
    }
    Ok(())
}

pub fn validate_compute_artifact_path(path: &str) -> Result<()> {
    if path.trim().is_empty()
        || path.len() > MAX_COMPUTE_ARTIFACT_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || !path.starts_with("artifacts/")
    {
        bail!("compute artifact path is invalid");
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!("compute artifact path is invalid");
        }
        if !segment
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
        {
            bail!("compute artifact path is invalid");
        }
    }
    Ok(())
}

pub fn validate_compute_input_file_path(path: &str) -> Result<()> {
    if path.trim().is_empty()
        || path.len() > MAX_COMPUTE_ARTIFACT_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path == "out.json"
        || path.starts_with("artifacts/")
    {
        bail!("compute input file path is invalid");
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!("compute input file path is invalid");
        }
        if !segment
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
        {
            bail!("compute input file path is invalid");
        }
    }
    Ok(())
}

fn validate_compute_workload(workload: &ComputeWorkload) -> Result<()> {
    if let ComputeWorkload::WasiPreview1 {
        module_hex,
        module_ref,
        args,
        env,
    } = workload
    {
        match (module_hex, module_ref) {
            (Some(module_hex), None) => {
                let module = decode_hex_limited(module_hex, MAX_WASI_MODULE_BYTES, "wasi module")?;
                if module.len() < 8 || &module[..4] != b"\0asm" {
                    bail!("wasi module is not a WebAssembly binary");
                }
            }
            (None, Some(module_ref)) => validate_compute_module_ref(module_ref)?,
            (Some(_), Some(_)) => {
                bail!("wasi workload must not include both module_hex and module_ref")
            }
            (None, None) => bail!("wasi workload requires module_hex or module_ref"),
        }
        if args.len() > MAX_WASI_ARGS {
            bail!("wasi workload has too many args");
        }
        for arg in args {
            if arg.len() > MAX_WASI_ARG_BYTES || arg.contains('\0') {
                bail!("wasi workload arg is invalid");
            }
        }
        if env.len() > MAX_WASI_ENV_VARS {
            bail!("wasi workload has too many env vars");
        }
        for (key, value) in env {
            validate_wasi_env_var(key, value)?;
        }
    }
    Ok(())
}

pub fn compute_wasi_module_ref(workload: &ComputeWorkload) -> Option<&ComputeModuleRef> {
    match workload {
        ComputeWorkload::WasiPreview1 { module_ref, .. } => module_ref.as_ref(),
        _ => None,
    }
}

pub fn validate_compute_module_ref(module_ref: &ComputeModuleRef) -> Result<()> {
    if module_ref.contract_id.trim().is_empty()
        || module_ref.contract_id.len() > MAX_STORAGE_CONTRACT_ID_BYTES
    {
        bail!("compute module_ref contract_id is invalid");
    }
    if module_ref.host_url.trim().is_empty()
        || module_ref.host_url.len() > MAX_WASI_MODULE_HOST_URL_BYTES
    {
        bail!("compute module_ref host_url is invalid");
    }
    let parsed = Url::parse(&module_ref.host_url)
        .map_err(|_| anyhow!("compute module_ref host_url is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        bail!("compute module_ref host_url is invalid");
    }
    validate_compute_module_path(&module_ref.path)?;
    validate_sha256_hex(&module_ref.sha256, "compute module_ref sha256")?;
    validate_sha256_hex(&module_ref.merkle_root, "compute module_ref merkle_root")?;
    if module_ref.size_bytes == 0 || module_ref.size_bytes > MAX_WASI_MODULE_REF_BYTES {
        bail!("compute module_ref size_bytes is invalid");
    }
    Ok(())
}

pub fn validate_compute_module_path(path: &str) -> Result<()> {
    if path.trim().is_empty()
        || path.len() > MAX_STORAGE_MANIFEST_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
    {
        bail!("compute module_ref path is invalid");
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!("compute module_ref path is invalid");
        }
        if !segment
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
        {
            bail!("compute module_ref path is invalid");
        }
    }
    Ok(())
}

fn validate_wasi_env_var(key: &str, value: &str) -> Result<()> {
    if key.trim().is_empty()
        || key.len() > MAX_WASI_ENV_KEY_BYTES
        || key.contains('\0')
        || key.contains('=')
        || !key
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        bail!("wasi workload env key is invalid");
    }
    if value.len() > MAX_WASI_ENV_VALUE_BYTES || value.contains('\0') {
        bail!("wasi workload env value is invalid");
    }
    Ok(())
}

pub fn validate_compute_shard_spec(
    workload: &ComputeWorkload,
    shard: &ComputeShardSpec,
) -> Result<()> {
    if shard.shard_id.trim().is_empty() || shard.shard_id.len() > MAX_COMPUTE_SHARD_ID_BYTES {
        bail!("compute shard_id is invalid");
    }
    match (workload, &shard.input) {
        (ComputeWorkload::IntegerMap { .. }, ComputeShardInput::Integers { values }) => {
            if values.is_empty() || values.len() > MAX_COMPUTE_INTEGERS_PER_SHARD {
                bail!("integer compute shard has an invalid value count");
            }
            if values
                .iter()
                .any(|value| value.abs() > MAX_COMPUTE_INTEGER_ABS)
            {
                bail!("integer compute shard value is outside the allowed range");
            }
        }
        (ComputeWorkload::MonteCarloPi, ComputeShardInput::MonteCarlo { samples, .. }) => {
            if *samples == 0 || *samples > MAX_MONTE_CARLO_SAMPLES_PER_SHARD {
                bail!("monte_carlo_pi shard sample count is invalid");
            }
        }
        (ComputeWorkload::WasiPreview1 { .. }, ComputeShardInput::Wasi { stdin_hex, files }) => {
            let mut total_bytes = 0usize;
            if let Some(stdin_hex) = stdin_hex {
                total_bytes = total_bytes
                    .checked_add(
                        decode_hex_limited(stdin_hex, MAX_WASI_INPUT_FILE_BYTES, "wasi stdin")?
                            .len(),
                    )
                    .ok_or_else(|| anyhow!("wasi input size overflow"))?;
            }
            if files.len() > MAX_WASI_INPUT_FILES {
                bail!("wasi shard has too many input files");
            }
            for (path, contents_hex) in files {
                validate_compute_input_file_path(path)?;
                total_bytes = total_bytes
                    .checked_add(
                        decode_hex_limited(
                            contents_hex,
                            MAX_WASI_INPUT_FILE_BYTES,
                            "wasi input file",
                        )?
                        .len(),
                    )
                    .ok_or_else(|| anyhow!("wasi input size overflow"))?;
            }
            if total_bytes > MAX_WASI_INPUT_TOTAL_BYTES {
                bail!("wasi shard input total exceeds maximum size");
            }
        }
        (ComputeWorkload::IntegerMap { .. }, _) => {
            bail!("integer compute workload requires integer shards")
        }
        (ComputeWorkload::MonteCarloPi, _) => {
            bail!("monte_carlo_pi workload requires monte_carlo shards")
        }
        (ComputeWorkload::WasiPreview1 { .. }, _) => bail!("wasi workload requires wasi shards"),
    }
    Ok(())
}

pub fn validate_compute_output(output: &ComputeShardOutput) -> Result<()> {
    if output.shard_id.trim().is_empty() || output.shard_id.len() > MAX_COMPUTE_SHARD_ID_BYTES {
        bail!("compute output shard_id is invalid");
    }
    let serialized = serde_json::to_vec(output)?;
    if serialized.len() > MAX_COMPUTE_OUTPUT_BYTES {
        bail!("compute shard output exceeds maximum size");
    }
    if output.success && output.output.is_none() {
        bail!("successful compute shard output is missing output");
    }
    if !output.success
        && output
            .error
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        bail!("failed compute shard output is missing error");
    }
    if output.stdout_sample.as_deref().unwrap_or_default().len() > MAX_COMPUTE_STDIO_BYTES {
        bail!("compute stdout sample exceeds maximum size");
    }
    if output.stderr_sample.as_deref().unwrap_or_default().len() > MAX_COMPUTE_STDIO_BYTES {
        bail!("compute stderr sample exceeds maximum size");
    }
    if output.artifacts.len() > MAX_COMPUTE_ARTIFACTS {
        bail!("compute shard output has too many artifacts");
    }
    for artifact in &output.artifacts {
        validate_compute_artifact_path(&artifact.path)?;
        validate_sha256_hex(&artifact.sha256, "compute artifact sha256")?;
        if artifact.size_bytes > MAX_COMPUTE_ARTIFACT_BYTES {
            bail!("compute artifact size exceeds maximum size");
        }
        if artifact.provider.trim().is_empty() {
            bail!("compute artifact provider is invalid");
        }
        if artifact.uri.trim().is_empty() || artifact.uri.len() > 1024 {
            bail!("compute artifact uri is invalid");
        }
    }
    Ok(())
}

pub fn validate_compute_output_artifacts(
    policy: &ComputeArtifactPolicy,
    output: &ComputeShardOutput,
) -> Result<()> {
    validate_compute_artifact_policy(policy)?;
    validate_compute_output(output)?;
    let declared = policy
        .outputs
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for artifact in &output.artifacts {
        let declared_artifact = declared
            .get(&artifact.path)
            .ok_or_else(|| anyhow!("compute artifact was not declared by policy"))?;
        if !seen.insert(artifact.path.clone()) {
            bail!("compute artifact appears more than once");
        }
        let max_bytes = declared_artifact
            .max_bytes
            .unwrap_or(policy.max_total_bytes);
        if artifact.size_bytes > max_bytes {
            bail!("compute artifact exceeds declared max_bytes");
        }
        if artifact.content_type != declared_artifact.content_type {
            bail!("compute artifact content_type does not match policy");
        }
        total = total
            .checked_add(artifact.size_bytes)
            .ok_or_else(|| anyhow!("compute artifact total size overflow"))?;
    }
    if total > policy.max_total_bytes {
        bail!("compute artifacts exceed policy max_total_bytes");
    }
    if output.success {
        for artifact in &policy.outputs {
            if artifact.required && !seen.contains(&artifact.path) {
                bail!("successful compute output is missing a required artifact");
            }
        }
    }
    Ok(())
}

pub fn execute_compute_shard(
    workload: &ComputeWorkload,
    shard: &ComputeShardSpec,
) -> Result<ComputeShardOutput> {
    validate_compute_shard_spec(workload, shard)?;
    let started = Instant::now();
    let result = match (workload, &shard.input) {
        (ComputeWorkload::IntegerMap { operation }, ComputeShardInput::Integers { values }) => {
            execute_integer_shard(operation, values)
        }
        (ComputeWorkload::MonteCarloPi, ComputeShardInput::MonteCarlo { samples, seed }) => {
            Ok(execute_monte_carlo_pi(*samples, *seed))
        }
        (ComputeWorkload::WasiPreview1 { .. }, _) => {
            bail!("wasi compute shards require the sandbox runner")
        }
        _ => bail!("compute shard input does not match workload"),
    };
    let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    match result {
        Ok(output) => Ok(ComputeShardOutput {
            shard_id: shard.shard_id.clone(),
            success: true,
            latency_ms,
            output: Some(output),
            error: None,
            artifacts: Vec::new(),
            stdout_sample: None,
            stderr_sample: None,
        }),
        Err(error) => Ok(ComputeShardOutput {
            shard_id: shard.shard_id.clone(),
            success: false,
            latency_ms,
            output: None,
            error: Some(error.to_string()),
            artifacts: Vec::new(),
            stdout_sample: None,
            stderr_sample: None,
        }),
    }
}

pub fn reduce_compute_outputs(
    spec: &ComputeJobSpec,
    outputs: &[ComputeShardOutput],
) -> Result<Value> {
    validate_compute_job_spec(spec)?;
    if outputs.len() != spec.shards.len() {
        bail!("compute reducer received the wrong number of shard outputs");
    }
    let expected = spec
        .shards
        .iter()
        .map(|shard| shard.shard_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let actual = outputs
        .iter()
        .map(|output| output.shard_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        bail!("compute reducer shard_id set does not match the job spec");
    }
    for output in outputs {
        validate_compute_output(output)?;
        if !output.success {
            bail!("compute shard {} failed", output.shard_id);
        }
    }

    match spec.reducer {
        ComputeReducer::Sum => reduce_i64_field(outputs, "sum").map(|sum| json!({ "sum": sum })),
        ComputeReducer::SumSquares => {
            reduce_i64_field(outputs, "sum_squares").map(|sum| json!({ "sum_squares": sum }))
        }
        ComputeReducer::Count => {
            reduce_u64_field(outputs, "count").map(|count| json!({ "count": count }))
        }
        ComputeReducer::MinMax => reduce_min_max(outputs),
        ComputeReducer::MonteCarloPi => reduce_monte_carlo_pi(outputs),
        ComputeReducer::ShardOutputs => Ok(json!({
            "shards": outputs
                .iter()
                .map(|output| {
                    json!({
                        "shard_id": output.shard_id,
                        "output": output.output,
                        "artifacts": output.artifacts,
                    })
                })
                .collect::<Vec<_>>()
        })),
    }
}

fn validate_reducer_matches_workload(
    workload: &ComputeWorkload,
    reducer: &ComputeReducer,
) -> Result<()> {
    match (workload, reducer) {
        (
            ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::Sum,
            },
            ComputeReducer::Sum | ComputeReducer::ShardOutputs,
        )
        | (
            ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::SumSquares,
            },
            ComputeReducer::SumSquares | ComputeReducer::ShardOutputs,
        )
        | (
            ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::Count,
            },
            ComputeReducer::Count | ComputeReducer::ShardOutputs,
        )
        | (
            ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::MinMax,
            },
            ComputeReducer::MinMax | ComputeReducer::ShardOutputs,
        )
        | (
            ComputeWorkload::MonteCarloPi,
            ComputeReducer::MonteCarloPi | ComputeReducer::ShardOutputs,
        )
        | (ComputeWorkload::WasiPreview1 { .. }, ComputeReducer::ShardOutputs) => Ok(()),
        _ => bail!("compute reducer does not match workload"),
    }
}

pub fn decode_hex_limited(input: &str, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        bail!("{label} hex has an odd length");
    }
    if input.len() / 2 > max_bytes {
        bail!("{label} exceeds maximum size");
    }
    hex::decode(input).map_err(|error| anyhow!("{label} hex is invalid: {error}"))
}

pub fn validate_sha256_hex(input: &str, label: &str) -> Result<()> {
    if input.len() != 64 || !input.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        bail!("{label} must be a sha256 hex digest");
    }
    Ok(())
}

fn execute_integer_shard(operation: &ComputeIntegerOperation, values: &[i64]) -> Result<Value> {
    match operation {
        ComputeIntegerOperation::Sum => {
            let sum = checked_sum(values)?;
            Ok(json!({ "sum": sum, "count": values.len() as u64 }))
        }
        ComputeIntegerOperation::SumSquares => {
            let mut sum = 0i64;
            for value in values {
                let square = value
                    .checked_mul(*value)
                    .ok_or_else(|| anyhow!("integer square overflow"))?;
                sum = sum
                    .checked_add(square)
                    .ok_or_else(|| anyhow!("sum_squares overflow"))?;
            }
            Ok(json!({ "sum_squares": sum, "count": values.len() as u64 }))
        }
        ComputeIntegerOperation::Count => Ok(json!({ "count": values.len() as u64 })),
        ComputeIntegerOperation::MinMax => {
            let min = values
                .iter()
                .min()
                .ok_or_else(|| anyhow!("empty integer shard"))?;
            let max = values
                .iter()
                .max()
                .ok_or_else(|| anyhow!("empty integer shard"))?;
            Ok(json!({ "min": min, "max": max, "count": values.len() as u64 }))
        }
    }
}

fn execute_monte_carlo_pi(samples: u64, seed: u64) -> Value {
    let mut state = seed;
    let mut inside = 0u64;
    let scale = 1u128 << 53;
    let radius_squared = scale * scale;
    for _ in 0..samples {
        let x = splitmix64_next(&mut state) >> 11;
        let y = splitmix64_next(&mut state) >> 11;
        let x = u128::from(x);
        let y = u128::from(y);
        if x * x + y * y <= radius_squared {
            inside += 1;
        }
    }
    json!({ "inside": inside, "samples": samples })
}

fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn checked_sum(values: &[i64]) -> Result<i64> {
    values.iter().try_fold(0i64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| anyhow!("integer sum overflow"))
    })
}

fn reduce_i64_field(outputs: &[ComputeShardOutput], field: &str) -> Result<i64> {
    outputs.iter().try_fold(0i64, |sum, output| {
        let value = output_value(output)?
            .get(field)
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("compute output is missing integer field {field}"))?;
        sum.checked_add(value)
            .ok_or_else(|| anyhow!("compute reducer overflow"))
    })
}

fn reduce_u64_field(outputs: &[ComputeShardOutput], field: &str) -> Result<u64> {
    outputs.iter().try_fold(0u64, |sum, output| {
        let value = output_value(output)?
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("compute output is missing unsigned field {field}"))?;
        sum.checked_add(value)
            .ok_or_else(|| anyhow!("compute reducer overflow"))
    })
}

fn reduce_min_max(outputs: &[ComputeShardOutput]) -> Result<Value> {
    let mut global_min: Option<i64> = None;
    let mut global_max: Option<i64> = None;
    let mut count = 0u64;
    for output in outputs {
        let value = output_value(output)?;
        let min = value
            .get("min")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("compute output is missing min"))?;
        let max = value
            .get("max")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("compute output is missing max"))?;
        let shard_count = value
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("compute output is missing count"))?;
        global_min = Some(global_min.map(|existing| existing.min(min)).unwrap_or(min));
        global_max = Some(global_max.map(|existing| existing.max(max)).unwrap_or(max));
        count = count
            .checked_add(shard_count)
            .ok_or_else(|| anyhow!("compute count overflow"))?;
    }
    Ok(json!({
        "min": global_min.ok_or_else(|| anyhow!("missing min"))?,
        "max": global_max.ok_or_else(|| anyhow!("missing max"))?,
        "count": count,
    }))
}

fn reduce_monte_carlo_pi(outputs: &[ComputeShardOutput]) -> Result<Value> {
    let inside = reduce_u64_field(outputs, "inside")?;
    let samples = reduce_u64_field(outputs, "samples")?;
    if samples == 0 {
        bail!("monte_carlo_pi reducer has zero samples");
    }
    let pi_micros = (u128::from(inside) * 4_000_000u128) / u128::from(samples);
    Ok(json!({
        "inside": inside,
        "samples": samples,
        "pi_micros": u64::try_from(pi_micros).map_err(|_| anyhow!("pi estimate overflow"))?,
    }))
}

fn output_value(output: &ComputeShardOutput) -> Result<&Value> {
    output
        .output
        .as_ref()
        .ok_or_else(|| anyhow!("compute shard output is missing output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_sum_reduces_across_shards() {
        let spec = ComputeJobSpec {
            request_id: "sum-1".into(),
            workload: ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::Sum,
            },
            shards: vec![
                ComputeShardSpec {
                    shard_id: "a".into(),
                    input: ComputeShardInput::Integers {
                        values: vec![1, 2, 3],
                    },
                },
                ComputeShardSpec {
                    shard_id: "b".into(),
                    input: ComputeShardInput::Integers { values: vec![4, 5] },
                },
            ],
            reducer: ComputeReducer::Sum,
            max_runtime_secs: 30,
            replication: 1,
            sandbox: default_compute_sandbox_policy(),
            artifact_policy: default_compute_artifact_policy(),
        };
        let outputs = spec
            .shards
            .iter()
            .map(|shard| execute_compute_shard(&spec.workload, shard).unwrap())
            .collect::<Vec<_>>();
        let reduced = reduce_compute_outputs(&spec, &outputs).unwrap();
        assert_eq!(reduced, json!({ "sum": 15 }));
    }

    #[test]
    fn monte_carlo_pi_is_deterministic() {
        let shard = ComputeShardSpec {
            shard_id: "mc".into(),
            input: ComputeShardInput::MonteCarlo {
                samples: 1_000,
                seed: 42,
            },
        };
        let left = execute_compute_shard(&ComputeWorkload::MonteCarloPi, &shard).unwrap();
        let right = execute_compute_shard(&ComputeWorkload::MonteCarloPi, &shard).unwrap();
        assert_eq!(left.output, right.output);
    }

    #[test]
    fn wasi_policy_rejects_host_escape_paths() {
        let spec = ComputeJobSpec {
            request_id: "wasi-1".into(),
            workload: ComputeWorkload::WasiPreview1 {
                module_hex: Some("0061736d01000000".into()),
                module_ref: None,
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            shards: vec![ComputeShardSpec {
                shard_id: "a".into(),
                input: ComputeShardInput::Wasi {
                    stdin_hex: None,
                    files: BTreeMap::from([("../secret".into(), "00".into())]),
                },
            }],
            reducer: ComputeReducer::ShardOutputs,
            max_runtime_secs: 30,
            replication: 1,
            sandbox: default_compute_sandbox_policy(),
            artifact_policy: default_compute_artifact_policy(),
        };
        assert!(validate_compute_job_spec(&spec).is_err());
    }
}
