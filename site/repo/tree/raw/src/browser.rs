use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs, process::Command};
use url::Url;

use crate::protocol::{Address, TxHash, compute_hash};

pub const BROWSER_CHECK_BASE_COST: u64 = 2_000_000;
pub const INCLUDED_BROWSER_STEPS: usize = 8;
pub const BROWSER_STEP_SURCHARGE_COST: u64 = 125_000;
pub const INCLUDED_BROWSER_RUNTIME_SECS: u64 = 20;
pub const BROWSER_RUNTIME_SURCHARGE_SECS: u64 = 10;
pub const BROWSER_RUNTIME_SURCHARGE_COST: u64 = 250_000;
pub const BROWSER_VIDEO_SURCHARGE_COST: u64 = 750_000;
pub const BROWSER_TRACE_SURCHARGE_COST: u64 = 250_000;
pub const MAX_BROWSER_PACKAGE_ID_BYTES: usize = 128;
pub const MAX_BROWSER_JOURNEY_ID_BYTES: usize = 128;
pub const MAX_BROWSER_STEPS: usize = 64;
pub const MAX_BROWSER_TEXT_BYTES: usize = 512;
pub const MAX_BROWSER_SELECTOR_BYTES: usize = 256;
pub const MAX_BROWSER_URL_BYTES: usize = 2_048;
pub const MAX_BROWSER_ARTIFACT_URI_BYTES: usize = 2_048;
pub const MAX_BROWSER_TAGS: usize = 32;
pub const MAX_BROWSER_TAG_KEY_BYTES: usize = 64;
pub const MAX_BROWSER_TAG_VALUE_BYTES: usize = 256;
pub const MAX_BROWSER_SECRETS: usize = 32;
pub const MAX_BROWSER_SECRET_KEY_BYTES: usize = 128;
pub const MAX_BROWSER_SECRET_VALUE_BYTES: usize = 2_048;
pub const MAX_BROWSER_RUNTIME_SECS: u64 = 600;
pub const MIN_BROWSER_RUNTIME_SECS: u64 = 1;
pub const MIN_BROWSER_STEP_TIMEOUT_MS: u64 = 100;
pub const MAX_BROWSER_STEP_TIMEOUT_MS: u64 = 60_000;
pub const MAX_BROWSER_VIEWPORT: u32 = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    Chromium,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCacheMode {
    #[default]
    Disabled,
    SessionState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserSelector {
    Css { value: String },
    Text { value: String },
    Label { value: String },
    Placeholder { value: String },
    TestId { value: String },
    Role { role: String, name: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserInputValue {
    Literal { value: String },
    SecretRef { key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserStep {
    Navigate {
        url: String,
    },
    Click {
        target: BrowserSelector,
    },
    Fill {
        target: BrowserSelector,
        value: BrowserInputValue,
    },
    Press {
        key: String,
    },
    WaitForText {
        text: String,
    },
    AssertText {
        text: String,
    },
    AssertUrlContains {
        text: String,
    },
    CaptureScreenshot {
        label: Option<String>,
    },
    OpenFreshContext {
        context_id: String,
    },
    CloseContext {
        context_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserRuntimeProfile {
    pub engine: BrowserEngine,
    pub engine_version: String,
    pub locale: String,
    pub timezone: String,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub color_scheme: String,
    #[serde(default)]
    pub block_service_workers: bool,
    #[serde(default)]
    pub cache_mode: BrowserCacheMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserArtifactPolicy {
    #[serde(default)]
    pub capture_video: bool,
    #[serde(default)]
    pub capture_trace: bool,
    #[serde(default)]
    pub capture_screenshot_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCachePolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserJourneySpec {
    pub journey_id: String,
    pub entry_url: String,
    #[serde(default)]
    pub steps: Vec<BrowserStep>,
    pub max_runtime_secs: u64,
    pub per_step_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserJourneyPackage {
    pub package_id: String,
    pub owner: Address,
    pub manifest_version: u32,
    pub runtime: BrowserRuntimeProfile,
    pub journey: BrowserJourneySpec,
    pub artifact_policy: BrowserArtifactPolicy,
    pub session_cache: SessionCachePolicy,
    pub approved_at: DateTime<Utc>,
    pub approved_by: Address,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCheckSpec {
    pub request_id: String,
    pub package: BrowserJourneyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserArtifactRef {
    pub uri: String,
    pub sha256: String,
    pub media_type: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserOutcomeClass {
    Success,
    StepFailed,
    NavigationTimeout,
    AssertionFailed,
    SelectorMissing,
    BrowserCrash,
    NetworkError,
    ScriptError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserExecution {
    pub success: bool,
    pub latency_ms: u64,
    pub failed_step_index: Option<usize>,
    pub final_url: Option<String>,
    pub outcome_class: BrowserOutcomeClass,
    pub console_error_count: u32,
    pub network_error_count: u32,
    pub screenshot_artifact: Option<BrowserArtifactRef>,
    pub trace_artifact: Option<BrowserArtifactRef>,
    pub video_artifact: Option<BrowserArtifactRef>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserReceiptBody {
    pub chain_id: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    #[serde(default)]
    pub monitor_id: Option<String>,
    #[serde(default)]
    pub slot_key: Option<String>,
    pub executor: Address,
    pub observed_at: DateTime<Utc>,
    pub package_hash: String,
    pub runtime_hash: String,
    pub latency_ms: u64,
    pub success: bool,
    pub failed_step_index: Option<usize>,
    pub final_url: Option<String>,
    pub outcome_class: BrowserOutcomeClass,
    pub console_error_count: u32,
    pub network_error_count: u32,
    pub screenshot_artifact: Option<BrowserArtifactRef>,
    pub trace_artifact: Option<BrowserArtifactRef>,
    pub video_artifact: Option<BrowserArtifactRef>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBrowserReceipt {
    pub id: String,
    pub body: BrowserReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserAgentLeaseBody {
    pub chain_id: String,
    pub lease_id: String,
    pub parent_validator: Address,
    pub agent_public_key: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    #[serde(default)]
    pub monitor_id: Option<String>,
    #[serde(default)]
    pub slot_key: Option<String>,
    pub spec: BrowserCheckSpec,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBrowserAgentLease {
    pub id: String,
    pub body: BrowserAgentLeaseBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegatedBrowserReceiptBody {
    pub chain_id: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    #[serde(default)]
    pub monitor_id: Option<String>,
    #[serde(default)]
    pub slot_key: Option<String>,
    pub agent_public_key: String,
    pub parent_validator: Address,
    #[serde(default)]
    pub lease_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub package_hash: String,
    pub runtime_hash: String,
    pub latency_ms: u64,
    pub success: bool,
    pub failed_step_index: Option<usize>,
    pub final_url: Option<String>,
    pub outcome_class: BrowserOutcomeClass,
    pub console_error_count: u32,
    pub network_error_count: u32,
    pub screenshot_artifact: Option<BrowserArtifactRef>,
    pub trace_artifact: Option<BrowserArtifactRef>,
    pub video_artifact: Option<BrowserArtifactRef>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDelegatedBrowserReceipt {
    pub id: String,
    pub body: DelegatedBrowserReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockBrowserBatch {
    pub tx_hash: TxHash,
    pub receipts: Vec<SignedBrowserReceipt>,
}

#[derive(Debug, Clone)]
pub struct BrowserRunnerConfig {
    pub program: Option<PathBuf>,
    pub args: Vec<String>,
    pub cache_dir: PathBuf,
    pub artifact_root: PathBuf,
    pub secret_store_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BrowserSecretStore {
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunnerArtifactPaths {
    screenshot_path: Option<String>,
    trace_path: Option<String>,
    video_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunnerInput {
    package: BrowserJourneyPackage,
    package_hash: String,
    runtime_hash: String,
    artifact_dir: String,
    session_state_path: Option<String>,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunnerOutput {
    success: bool,
    latency_ms: u64,
    failed_step_index: Option<usize>,
    final_url: Option<String>,
    outcome_class: BrowserOutcomeClass,
    console_error_count: u32,
    network_error_count: u32,
    screenshot_path: Option<String>,
    trace_path: Option<String>,
    video_path: Option<String>,
    error: Option<String>,
}

pub fn browser_package_hash(package: &BrowserJourneyPackage) -> Result<String> {
    validate_browser_journey_package(package)?;
    compute_hash(package)
}

pub fn browser_runtime_hash(runtime: &BrowserRuntimeProfile) -> Result<String> {
    validate_browser_runtime_profile(runtime)?;
    compute_hash(runtime)
}

pub fn browser_check_cost(spec: &BrowserCheckSpec) -> Result<u64> {
    validate_browser_check_spec(spec)?;

    let mut total = BROWSER_CHECK_BASE_COST;
    let step_count = spec.package.journey.steps.len();
    if step_count > INCLUDED_BROWSER_STEPS {
        let extra_steps = (step_count - INCLUDED_BROWSER_STEPS).div_ceil(4) as u64;
        total = total
            .checked_add(extra_steps * BROWSER_STEP_SURCHARGE_COST)
            .ok_or_else(|| anyhow!("browser check cost overflow"))?;
    }
    if spec.package.journey.max_runtime_secs > INCLUDED_BROWSER_RUNTIME_SECS {
        let extra_runtime = spec.package.journey.max_runtime_secs - INCLUDED_BROWSER_RUNTIME_SECS;
        let runtime_units = extra_runtime.div_ceil(BROWSER_RUNTIME_SURCHARGE_SECS);
        total = total
            .checked_add(runtime_units * BROWSER_RUNTIME_SURCHARGE_COST)
            .ok_or_else(|| anyhow!("browser check cost overflow"))?;
    }
    if spec.package.artifact_policy.capture_video {
        total = total
            .checked_add(BROWSER_VIDEO_SURCHARGE_COST)
            .ok_or_else(|| anyhow!("browser check cost overflow"))?;
    }
    if spec.package.artifact_policy.capture_trace {
        total = total
            .checked_add(BROWSER_TRACE_SURCHARGE_COST)
            .ok_or_else(|| anyhow!("browser check cost overflow"))?;
    }
    Ok(total)
}

pub fn validate_browser_check_spec(spec: &BrowserCheckSpec) -> Result<()> {
    if spec.request_id.trim().is_empty() {
        bail!("browser check request_id cannot be empty");
    }
    validate_browser_journey_package(&spec.package)
}

pub fn validate_browser_journey_package(package: &BrowserJourneyPackage) -> Result<()> {
    if package.package_id.trim().is_empty()
        || package.package_id.len() > MAX_BROWSER_PACKAGE_ID_BYTES
    {
        bail!("browser package_id is invalid");
    }
    if package.owner.trim().is_empty() {
        bail!("browser package owner cannot be empty");
    }
    if package.approved_by.trim().is_empty() {
        bail!("browser package approved_by cannot be empty");
    }
    if package.manifest_version == 0 {
        bail!("browser package manifest_version must be greater than zero");
    }
    validate_browser_runtime_profile(&package.runtime)?;
    validate_browser_journey_spec(&package.journey)?;
    validate_browser_artifact_policy(&package.artifact_policy)?;
    validate_session_cache_policy(&package.session_cache)?;
    validate_browser_tags(&package.tags)?;
    Ok(())
}

pub fn validate_browser_runtime_profile(runtime: &BrowserRuntimeProfile) -> Result<()> {
    if runtime.engine_version.trim().is_empty() {
        bail!("browser engine_version cannot be empty");
    }
    if runtime.locale.trim().is_empty() {
        bail!("browser locale cannot be empty");
    }
    if runtime.timezone.trim().is_empty() {
        bail!("browser timezone cannot be empty");
    }
    if runtime.color_scheme.trim().is_empty() {
        bail!("browser color_scheme cannot be empty");
    }
    if runtime.viewport_width == 0
        || runtime.viewport_height == 0
        || runtime.viewport_width > MAX_BROWSER_VIEWPORT
        || runtime.viewport_height > MAX_BROWSER_VIEWPORT
    {
        bail!("browser viewport is invalid");
    }
    Ok(())
}

pub fn validate_browser_journey_spec(spec: &BrowserJourneySpec) -> Result<()> {
    if spec.journey_id.trim().is_empty() || spec.journey_id.len() > MAX_BROWSER_JOURNEY_ID_BYTES {
        bail!("browser journey_id is invalid");
    }
    validate_browser_url(&spec.entry_url, "browser entry_url")?;
    if spec.steps.is_empty() {
        bail!("browser journey must include at least one step");
    }
    if spec.steps.len() > MAX_BROWSER_STEPS {
        bail!("browser journey has too many steps");
    }
    if spec.max_runtime_secs < MIN_BROWSER_RUNTIME_SECS
        || spec.max_runtime_secs > MAX_BROWSER_RUNTIME_SECS
    {
        bail!("browser max_runtime_secs is invalid");
    }
    if spec.per_step_timeout_ms < MIN_BROWSER_STEP_TIMEOUT_MS
        || spec.per_step_timeout_ms > MAX_BROWSER_STEP_TIMEOUT_MS
    {
        bail!("browser per_step_timeout_ms is invalid");
    }
    let mut open_contexts = BTreeSet::new();
    for step in &spec.steps {
        match step {
            BrowserStep::Navigate { url } => validate_browser_url(url, "browser navigate url")?,
            BrowserStep::Click { target } => validate_browser_selector(target)?,
            BrowserStep::Fill { target, value } => {
                validate_browser_selector(target)?;
                validate_browser_input_value(value)?;
            }
            BrowserStep::Press { key } => validate_browser_text(key, "browser press key")?,
            BrowserStep::WaitForText { text }
            | BrowserStep::AssertText { text }
            | BrowserStep::AssertUrlContains { text } => {
                validate_browser_text(text, "browser text assertion")?
            }
            BrowserStep::CaptureScreenshot { label } => {
                if let Some(label) = label {
                    validate_browser_text(label, "browser screenshot label")?;
                }
            }
            BrowserStep::OpenFreshContext { context_id } => {
                validate_browser_text(context_id, "browser context_id")?;
                open_contexts.insert(context_id.clone());
            }
            BrowserStep::CloseContext { context_id } => {
                validate_browser_text(context_id, "browser context_id")?;
            }
        }
    }
    Ok(())
}

fn validate_browser_artifact_policy(policy: &BrowserArtifactPolicy) -> Result<()> {
    if policy.capture_video && !policy.capture_trace && !policy.capture_screenshot_on_failure {
        // No-op validation hook to keep policy combinations explicit.
    }
    Ok(())
}

fn validate_session_cache_policy(policy: &SessionCachePolicy) -> Result<()> {
    if !policy.enabled {
        return Ok(());
    }
    if let Some(namespace) = &policy.namespace {
        validate_browser_text(namespace, "browser session cache namespace")?;
    }
    if policy.max_age_secs > 86_400 * 30 {
        bail!("browser session cache max_age_secs is too large");
    }
    Ok(())
}

fn validate_browser_tags(tags: &BTreeMap<String, String>) -> Result<()> {
    if tags.len() > MAX_BROWSER_TAGS {
        bail!("browser package has too many tags");
    }
    for (key, value) in tags {
        if key.trim().is_empty() || key.len() > MAX_BROWSER_TAG_KEY_BYTES {
            bail!("browser tag key is invalid");
        }
        if value.len() > MAX_BROWSER_TAG_VALUE_BYTES {
            bail!("browser tag value is invalid");
        }
    }
    Ok(())
}

fn validate_browser_selector(selector: &BrowserSelector) -> Result<()> {
    match selector {
        BrowserSelector::Css { value }
        | BrowserSelector::Text { value }
        | BrowserSelector::Label { value }
        | BrowserSelector::Placeholder { value }
        | BrowserSelector::TestId { value } => {
            validate_browser_text(value, "browser selector")?;
            if value.len() > MAX_BROWSER_SELECTOR_BYTES {
                bail!("browser selector exceeds maximum length");
            }
        }
        BrowserSelector::Role { role, name } => {
            validate_browser_text(role, "browser role")?;
            if let Some(name) = name {
                validate_browser_text(name, "browser role name")?;
            }
        }
    }
    Ok(())
}

fn validate_browser_input_value(value: &BrowserInputValue) -> Result<()> {
    match value {
        BrowserInputValue::Literal { value } => validate_browser_text(value, "browser literal")?,
        BrowserInputValue::SecretRef { key } => validate_browser_secret_key(key)?,
    }
    Ok(())
}

fn validate_browser_secret_key(key: &str) -> Result<()> {
    if key.trim().is_empty() || key.len() > MAX_BROWSER_SECRET_KEY_BYTES {
        bail!("browser secret key is invalid");
    }
    Ok(())
}

fn validate_browser_text(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_BROWSER_TEXT_BYTES {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_browser_url(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_BROWSER_URL_BYTES {
        bail!("{label} is invalid");
    }
    let url = Url::parse(value)?;
    match url.scheme() {
        "http" | "https" | "file" => {}
        _ => bail!("{label} must use http, https, or file"),
    }
    Ok(())
}

pub async fn execute_browser_check(
    spec: &BrowserCheckSpec,
    tx_hash: &str,
    config: &BrowserRunnerConfig,
) -> Result<BrowserExecution> {
    validate_browser_check_spec(spec)?;

    fs::create_dir_all(&config.cache_dir).await?;
    fs::create_dir_all(&config.artifact_root).await?;

    let package_hash = browser_package_hash(&spec.package)?;
    let runtime_hash = browser_runtime_hash(&spec.package.runtime)?;
    let artifact_dir = config
        .artifact_root
        .join(tx_hash)
        .join(format!("{}-{}", spec.package.package_id, package_hash));
    fs::create_dir_all(&artifact_dir).await?;

    let secrets = resolve_browser_secrets(spec, config.secret_store_path.as_deref()).await?;
    let session_state_path =
        resolve_session_state_path(spec, &package_hash, &config.cache_dir, &secrets).await?;
    let input = RunnerInput {
        package: spec.package.clone(),
        package_hash,
        runtime_hash,
        artifact_dir: artifact_dir.to_string_lossy().into_owned(),
        session_state_path: session_state_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        secrets,
    };
    let output = run_browser_runner(&input, config).await?;
    let artifacts = RunnerArtifactPaths {
        screenshot_path: output.screenshot_path.clone(),
        trace_path: output.trace_path.clone(),
        video_path: output.video_path.clone(),
    };
    Ok(BrowserExecution {
        success: output.success,
        latency_ms: output.latency_ms,
        failed_step_index: output.failed_step_index,
        final_url: output.final_url,
        outcome_class: output.outcome_class,
        console_error_count: output.console_error_count,
        network_error_count: output.network_error_count,
        screenshot_artifact: materialize_artifact(
            tx_hash,
            artifacts.screenshot_path.as_deref(),
            "image/png",
        )
        .await?,
        trace_artifact: materialize_artifact(
            tx_hash,
            artifacts.trace_path.as_deref(),
            "application/zip",
        )
        .await?,
        video_artifact: materialize_artifact(
            tx_hash,
            artifacts.video_path.as_deref(),
            "video/webm",
        )
        .await?,
        error: output.error,
    })
}

async fn resolve_browser_secrets(
    spec: &BrowserCheckSpec,
    secret_store_path: Option<&Path>,
) -> Result<BTreeMap<String, String>> {
    let required = collect_secret_refs(&spec.package);
    if required.is_empty() {
        return Ok(BTreeMap::new());
    }
    let Some(path) = secret_store_path else {
        bail!("browser check requires secret refs but no secret store is configured");
    };
    let payload = fs::read(path)
        .await
        .with_context(|| format!("failed to read browser secret store {}", path.display()))?;
    let store: BrowserSecretStore = serde_json::from_slice(&payload)?;
    if store.secrets.len() > MAX_BROWSER_SECRETS {
        bail!("browser secret store has too many entries");
    }
    let mut resolved = BTreeMap::new();
    for key in required {
        let value = store
            .secrets
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("missing browser secret ref {key}"))?;
        if value.len() > MAX_BROWSER_SECRET_VALUE_BYTES {
            bail!("browser secret value is too large");
        }
        resolved.insert(key, value);
    }
    Ok(resolved)
}

fn collect_secret_refs(package: &BrowserJourneyPackage) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for step in &package.journey.steps {
        if let BrowserStep::Fill {
            value: BrowserInputValue::SecretRef { key },
            ..
        } = step
        {
            refs.insert(key.clone());
        }
    }
    refs
}

async fn resolve_session_state_path(
    spec: &BrowserCheckSpec,
    package_hash: &str,
    cache_dir: &Path,
    secrets: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    let policy = &spec.package.session_cache;
    if !policy.enabled || spec.package.runtime.cache_mode != BrowserCacheMode::SessionState {
        return Ok(None);
    }
    let namespace = policy
        .namespace
        .clone()
        .unwrap_or_else(|| spec.package.package_id.clone());
    let secret_fingerprint = if secrets.is_empty() {
        "public".to_string()
    } else {
        let secret_lengths = secrets
            .iter()
            .map(|(key, value)| (key.clone(), value.len()))
            .collect::<Vec<_>>();
        compute_hash(&(package_hash.to_string(), namespace.clone(), secret_lengths))?
    };
    let path = cache_dir
        .join("session_state")
        .join(package_hash)
        .join(format!("{namespace}-{secret_fingerprint}.json"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    if policy.max_age_secs > 0
        && let Ok(metadata) = fs::metadata(&path).await
        && let Ok(modified) = metadata.modified()
    {
        let age = modified.elapsed().unwrap_or_default().as_secs();
        if age > policy.max_age_secs {
            let _ = fs::remove_file(&path).await;
        }
    }
    Ok(Some(path))
}

async fn run_browser_runner(
    input: &RunnerInput,
    config: &BrowserRunnerConfig,
) -> Result<RunnerOutput> {
    let run_id = compute_hash(&(input.package_hash.clone(), Utc::now().timestamp_nanos_opt()))?;
    let temp_dir = std::env::temp_dir().join(format!("gossip-protocol-browser-{run_id}"));
    fs::create_dir_all(&temp_dir).await?;
    let input_path = temp_dir.join("input.json");
    let output_path = temp_dir.join("output.json");
    fs::write(&input_path, serde_json::to_vec_pretty(input)?).await?;

    let mut command = if let Some(program) = &config.program {
        Command::new(program)
    } else {
        let mut command = Command::new("node");
        command.arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("browser_runner")
                .join("runner.mjs"),
        );
        command.current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("browser_runner"));
        command
    };
    command
        .args(&config.args)
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = command.output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("browser runner failed: {}", stderr.trim());
    }
    let payload = fs::read(&output_path).await?;
    let parsed: RunnerOutput = serde_json::from_slice(&payload)?;
    let _ = fs::remove_dir_all(&temp_dir).await;
    Ok(parsed)
}

async fn materialize_artifact(
    tx_hash: &str,
    path: Option<&str>,
    media_type: &str,
) -> Result<Option<BrowserArtifactRef>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if path.trim().is_empty() || path.len() > MAX_BROWSER_ARTIFACT_URI_BYTES {
        bail!("browser artifact path is invalid");
    }
    let bytes = fs::read(path).await?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("browser artifact filename is invalid"))?;
    Ok(Some(BrowserArtifactRef {
        uri: format!("artifact://browser-checks/{tx_hash}/{file_name}"),
        sha256,
        media_type: media_type.to_string(),
        bytes: bytes.len() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_package() -> BrowserJourneyPackage {
        BrowserJourneyPackage {
            package_id: "wiki-cat".into(),
            owner: "owner".into(),
            manifest_version: 1,
            runtime: BrowserRuntimeProfile {
                engine: BrowserEngine::Chromium,
                engine_version: "1.54".into(),
                locale: "en-US".into(),
                timezone: "UTC".into(),
                viewport_width: 1280,
                viewport_height: 720,
                color_scheme: "light".into(),
                block_service_workers: true,
                cache_mode: BrowserCacheMode::SessionState,
            },
            journey: BrowserJourneySpec {
                journey_id: "wiki-cat".into(),
                entry_url: "https://www.wikipedia.org".into(),
                steps: vec![
                    BrowserStep::Navigate {
                        url: "https://www.wikipedia.org".into(),
                    },
                    BrowserStep::Fill {
                        target: BrowserSelector::Css {
                            value: "#searchInput".into(),
                        },
                        value: BrowserInputValue::Literal {
                            value: "cat".into(),
                        },
                    },
                    BrowserStep::Press {
                        key: "Enter".into(),
                    },
                    BrowserStep::AssertText { text: "Cat".into() },
                ],
                max_runtime_secs: 90,
                per_step_timeout_ms: 5_000,
            },
            artifact_policy: BrowserArtifactPolicy {
                capture_video: true,
                capture_trace: true,
                capture_screenshot_on_failure: true,
            },
            session_cache: SessionCachePolicy {
                enabled: true,
                namespace: Some("wiki".into()),
                max_age_secs: 3_600,
            },
            approved_at: Utc::now(),
            approved_by: "approver".into(),
            tags: BTreeMap::new(),
        }
    }

    #[test]
    fn browser_package_validation_accepts_canonical_package() {
        validate_browser_journey_package(&sample_package()).unwrap();
    }

    #[test]
    fn browser_package_validation_rejects_empty_steps() {
        let mut package = sample_package();
        package.journey.steps.clear();
        assert!(validate_browser_journey_package(&package).is_err());
    }

    #[test]
    fn browser_check_cost_scales_with_runtime_and_artifacts() {
        let simple = BrowserCheckSpec {
            request_id: "simple".into(),
            package: sample_package(),
        };
        let mut expensive = simple.clone();
        expensive.package.journey.max_runtime_secs = 180;
        expensive.package.journey.steps.extend(vec![
            BrowserStep::AssertUrlContains {
                text: "wiki".into(),
            };
            8
        ]);
        assert!(browser_check_cost(&expensive).unwrap() > browser_check_cost(&simple).unwrap());
    }
}
