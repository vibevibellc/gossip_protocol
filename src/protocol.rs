use std::{collections::BTreeMap, str::FromStr};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::browser::{
    BlockBrowserBatch, BrowserCheckSpec, BrowserJourneyPackage, SignedBrowserReceipt,
    browser_check_cost,
};
use crate::compute::{BlockComputeBatch, ComputeJobSpec, SignedComputeReceipt};

pub const TOKEN_DECIMALS: u32 = 6;
pub const MICRO_HT: u64 = 1_000_000;
pub const MICRO_ST: u64 = 1_000_000;
pub const MICRO_CT: u64 = 1_000_000;
pub const MICRO_DNS: u64 = 1_000_000;
pub const HEALTH_CHECK_BASE_COST: u64 = MICRO_HT;
pub const INCLUDED_HEALTH_TIMEOUT_MS: u64 = 3_000;
pub const HEALTH_TIMEOUT_SURCHARGE_STEP_MS: u64 = 1_000;
pub const HEALTH_TIMEOUT_SURCHARGE_STEP_COST: u64 = 100_000;
pub const INCLUDED_HEALTH_COMPLEXITY_UNITS: usize = 8;
pub const HEALTH_COMPLEXITY_SURCHARGE_UNIT_COST: u64 = 25_000;
pub const INCLUDED_HEALTH_BODY_BYTES: usize = 1_024;
pub const HEALTH_BODY_SURCHARGE_PER_KIB: u64 = 100_000;
pub const MAX_BODY_SAMPLE_BYTES: usize = 2048;
pub const MAX_HEALTH_URL_LENGTH: usize = 2_048;
pub const MAX_HEALTH_HEADERS: usize = 16;
pub const MAX_HEALTH_QUERY_PARAMS: usize = 16;
pub const MAX_HEALTH_ASSERTIONS: usize = 16;
pub const MAX_HEADER_NAME_BYTES: usize = 128;
pub const MAX_HEADER_VALUE_BYTES: usize = 1_024;
pub const MAX_QUERY_KEY_BYTES: usize = 128;
pub const MAX_QUERY_VALUE_BYTES: usize = 512;
pub const MAX_ASSERTION_TEXT_BYTES: usize = 512;
pub const MAX_JSON_BODY_BYTES: usize = 8_192;
pub const MIN_TIMEOUT_MS: u64 = 100;
pub const MAX_TIMEOUT_MS: u64 = 30_000;
pub const MAX_BLOCK_TRANSACTIONS: usize = 32;
pub const MAX_BLOCK_BODY_BYTES: usize = 262_144;
pub const DEFAULT_SWAP_QUOTE_TTL_SECS: u64 = 300;
pub const MAX_SWAP_QUOTE_TTL_SECS: u64 = 3_600;
pub const MONITOR_SLOT_RESERVATION_FEE: u64 = 10_000;
pub const MONITOR_PING_INGRESS_FEE: u64 = 1_000;
pub const MONITOR_ALERT_DELIVERY_FEE: u64 = 5_000;
pub const MONITOR_MIN_INTERVAL_SECS: u64 = 60;
pub const MONITOR_MAX_GRACE_SECS: u64 = 86_400;
pub const MAX_MONITOR_ID_BYTES: usize = 128;
pub const MAX_MONITOR_SLUG_BYTES: usize = 128;
pub const MAX_MONITOR_TAGS: usize = 32;
pub const MAX_MONITOR_TAG_KEY_BYTES: usize = 64;
pub const MAX_MONITOR_TAG_VALUE_BYTES: usize = 256;
pub const MAX_NOTIFICATION_POLICY_ID_BYTES: usize = 128;
pub const MAX_LOG_CAPTURE_BYTES: u32 = 16_384;
pub const MAX_PING_BODY_SAMPLE_BYTES: usize = 4_096;
pub const MAX_HEARTBEAT_NONCE_BYTES: usize = 128;
pub const MAX_DELEGATED_AGENT_TAG_BYTES: usize = 64;
pub const MAX_CONFIRMATION_BATCHES: usize = 64;
pub const STORAGE_BILLING_QUANTUM_BYTES: u64 = 64 * 1024 * 1024;
pub const STORAGE_REWARD_PER_QUANTUM_SECOND: u64 = MICRO_ST;
pub const DEFAULT_STORAGE_CHUNK_SIZE_BYTES: u64 = 64 * 1024;
pub const DEFAULT_STORAGE_PROOF_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_STORAGE_PROOF_SAMPLE_COUNT: u16 = 4;
pub const MIN_STORAGE_CHUNK_SIZE_BYTES: u64 = 1_024;
pub const MAX_STORAGE_CHUNK_SIZE_BYTES: u64 = STORAGE_BILLING_QUANTUM_BYTES;
pub const MAX_STORAGE_CONTRACT_BYTES: u64 = 1_099_511_627_776;
pub const MAX_STORAGE_DURATION_SECS: u64 = 31_536_000;
pub const MAX_STORAGE_PROOF_INTERVAL_SECS: u64 = 86_400;
pub const MAX_STORAGE_PROOF_SAMPLE_COUNT: u16 = 64;
pub const MAX_STORAGE_MERKLE_PROOF_DEPTH: usize = 64;
pub const MAX_STORAGE_CONTRACT_ID_BYTES: usize = 128;
pub const MAX_STORAGE_MANIFEST_PATH_BYTES: usize = 512;
pub const MAX_STORAGE_MANIFEST_CONTENT_TYPES: usize = 64;
pub const MAX_STORAGE_CONTENT_TYPE_BYTES: usize = 128;
pub const STATIC_SITE_CRITICAL_PREFIX_TARGET_BYTES: u32 = 14 * 1024;
pub const MAX_STATIC_SITE_CRITICAL_PREFIX_BYTES: u32 = 16 * 1024;
pub const DNS_LEASE_COST_PER_SUBDOMAIN_SECOND: u64 = MICRO_DNS;
pub const MAX_DOMAIN_OFFERING_ID_BYTES: usize = 128;
pub const MAX_DOMAIN_LABEL_BYTES: usize = 63;
pub const MAX_DOMAIN_SUFFIX_BYTES: usize = 253;
pub const MAX_DOMAIN_GATEWAY_URL_BYTES: usize = 512;
pub const MAX_DOMAIN_LEASE_DURATION_SECS: u64 = 31_536_000;

pub type Address = String;
pub type TxHash = String;
pub type ReceiptId = String;
pub type BlockHash = String;
pub type ApprovalId = String;
pub type MonitorId = String;
pub type HeartbeatObservationId = String;
pub type AlertFactId = String;
pub type SlotKey = String;
pub type StorageContractId = String;
pub type DomainOfferingId = String;
pub type DomainLeaseId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFanoutPolicy {
    OnePerValidator,
    KValidatorsMin { count: usize },
    AllValidators,
    KAgentsWithRegionDiversity { count: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthHttpMethod {
    Get,
    Head,
    Post,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAssertion {
    JsonFieldExists { path: String },
    JsonFieldEquals { path: String, value: Value },
    HeaderEquals { name: String, value: String },
    BodyContains { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckSpec {
    pub request_id: String,
    pub url: String,
    pub method: HealthHttpMethod,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub assertions: Vec<ResponseAssertion>,
    pub body_json: Option<Value>,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub allow_private_targets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleSpec {
    Interval {
        every_secs: u64,
        anchor_at: DateTime<Utc>,
    },
    CronUtc {
        expr: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatAuth {
    SecretUrl {
        token_hash: String,
    },
    DelegatedKey {
        key_id: String,
        public_key: String,
    },
    Dual {
        token_hash: String,
        key_id: String,
        public_key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalPolicy {
    SuccessOnly,
    StartAndSuccess { run_timeout_secs: u64 },
    StartSuccessFail { run_timeout_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissPolicy {
    RecordOnly,
    ConfirmWithValidators {
        fanout: ProbeFanoutPolicy,
    },
    ConfirmWithDelegatedAgents {
        fanout: ProbeFanoutPolicy,
        require_region_diversity: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogCapturePolicy {
    #[default]
    None,
    CaptureText {
        max_bytes: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSpec {
    pub monitor_id: String,
    pub slug: Option<String>,
    pub schedule: ScheduleSpec,
    pub grace_secs: u64,
    #[serde(flatten)]
    pub pathway: MonitorPathway,
    pub notification_policy_id: Option<String>,
    #[serde(default)]
    pub log_capture: LogCapturePolicy,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "pathway", rename_all = "snake_case")]
pub enum MonitorPathway {
    Heartbeat {
        ping_auth: HeartbeatAuth,
        signal_policy: SignalPolicy,
        miss_policy: MissPolicy,
        confirmation_probe: Option<HealthCheckSpec>,
    },
    Browser {
        package: BrowserJourneyPackage,
    },
}

impl MonitorSpec {
    pub fn heartbeat_config(&self) -> Option<HeartbeatMonitorConfigRef<'_>> {
        match &self.pathway {
            MonitorPathway::Heartbeat {
                ping_auth,
                signal_policy,
                miss_policy,
                confirmation_probe,
            } => Some(HeartbeatMonitorConfigRef {
                ping_auth,
                signal_policy,
                miss_policy,
                confirmation_probe: confirmation_probe.as_ref(),
            }),
            MonitorPathway::Browser { .. } => None,
        }
    }

    pub fn browser_package(&self) -> Option<&BrowserJourneyPackage> {
        match &self.pathway {
            MonitorPathway::Browser { package } => Some(package),
            MonitorPathway::Heartbeat { .. } => None,
        }
    }

    pub fn is_heartbeat(&self) -> bool {
        self.heartbeat_config().is_some()
    }

    pub fn is_browser(&self) -> bool {
        self.browser_package().is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HeartbeatMonitorConfigRef<'a> {
    pub ping_auth: &'a HeartbeatAuth,
    pub signal_policy: &'a SignalPolicy,
    pub miss_policy: &'a MissPolicy,
    pub confirmation_probe: Option<&'a HealthCheckSpec>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatSignal {
    Success,
    Start,
    Fail,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatAuthMode {
    SecretUrl,
    DelegatedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MonitorEvaluationKind {
    SlotSatisfied,
    SlotMissed,
    InsufficientFunds,
    Recovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatObservationBody {
    pub chain_id: String,
    pub monitor_id: String,
    pub slot_key: String,
    pub signal: HeartbeatSignal,
    pub observed_at: DateTime<Utc>,
    pub observed_by: Address,
    pub body_sha256: Option<String>,
    pub body_sample: Option<String>,
    pub auth_mode: HeartbeatAuthMode,
    pub client_signature: Option<String>,
    pub client_key_id: Option<String>,
    pub client_timestamp: Option<DateTime<Utc>>,
    pub client_nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeatObservation {
    pub id: HeartbeatObservationId,
    pub body: HeartbeatObservationBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvaluation {
    pub monitor_id: String,
    pub slot_key: String,
    pub kind: MonitorEvaluationKind,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAgentLeaseBody {
    pub chain_id: String,
    pub lease_id: String,
    pub parent_validator: Address,
    pub agent_public_key: String,
    pub monitor_id: String,
    pub slot_key: String,
    pub request_id: String,
    pub spec: HealthCheckSpec,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProbeAgentLease {
    pub id: String,
    pub body: ProbeAgentLeaseBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedProbeReceiptBody {
    pub chain_id: String,
    pub monitor_id: String,
    pub slot_key: String,
    pub agent_public_key: String,
    pub parent_validator: Address,
    #[serde(default)]
    pub lease_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub region: Option<String>,
    pub network: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub response_status: Option<u16>,
    pub latency_ms: u64,
    pub success: bool,
    #[serde(default)]
    pub assertion_results: Vec<AssertionResult>,
    #[serde(default)]
    pub response_headers: BTreeMap<String, String>,
    pub response_body_sample: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegatedProbeReceipt {
    pub id: ReceiptId,
    pub body: DelegatedProbeReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfirmationBatch {
    pub monitor_id: String,
    pub slot_key: String,
    #[serde(default)]
    pub validator_receipts: Vec<SignedHealthReceipt>,
    #[serde(default)]
    pub delegated_receipts: Vec<SignedDelegatedProbeReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorBrowserBatch {
    pub monitor_id: String,
    pub slot_key: String,
    #[serde(default)]
    pub receipts: Vec<SignedBrowserReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Up,
    Running,
    Late,
    Down,
    Paused,
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorSlotStatus {
    Pending,
    Running,
    Ok,
    FailedExplicit,
    MissedUnconfirmed,
    MissedServiceReachable,
    DownConfirmed,
    RecoveredLate,
    Paused,
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSlotRecord {
    pub monitor_id: String,
    pub slot_key: String,
    pub slot_started_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub status: MonitorSlotStatus,
    pub finalized_at: DateTime<Utc>,
    pub observation_ids: Vec<String>,
    pub confirmation_success: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFact {
    pub id: AlertFactId,
    pub monitor_id: String,
    pub slot_key: String,
    pub status: MonitorSlotStatus,
    pub created_at: DateTime<Utc>,
    pub notification_policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageCompression {
    Brotli,
    Gzip,
    #[default]
    Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticSiteManifest {
    pub index_path: String,
    #[serde(default)]
    pub critical_prefix_hash: Option<String>,
    #[serde(default)]
    pub critical_prefix_bytes: Option<u32>,
    #[serde(default)]
    pub compression: StorageCompression,
    #[serde(default)]
    pub content_types: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    Encrypted,
    PublicRaw {
        #[serde(default)]
        manifest: Option<StaticSiteManifest>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageContractSpec {
    pub contract_id: StorageContractId,
    pub host: Address,
    pub mode: StorageMode,
    pub size_bytes: u64,
    #[serde(default = "default_storage_chunk_size_bytes")]
    pub chunk_size_bytes: u64,
    pub merkle_root: String,
    pub duration_secs: u64,
    #[serde(default = "default_storage_proof_interval_secs")]
    pub proof_interval_secs: u64,
    #[serde(default = "default_storage_proof_sample_count")]
    pub proof_sample_count: u16,
    #[serde(default = "default_storage_reward_rate_per_quantum_second")]
    pub reward_rate_per_64mib_second: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageContractStatus {
    Active,
    Cancelled,
    Expired,
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageContractRecord {
    pub contract_id: StorageContractId,
    pub owner: Address,
    pub host: Address,
    pub spec: StorageContractSpec,
    pub prepaid_balance: u64,
    pub status: StorageContractStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_proven_at: DateTime<Utc>,
    pub total_paid: u64,
    pub proof_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MerkleProofSide {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProofNode {
    pub side: MerkleProofSide,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageProofSample {
    pub chunk_index: u64,
    pub chunk_hash: String,
    #[serde(default)]
    pub proof: Vec<MerkleProofNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofReceiptBody {
    pub chain_id: String,
    pub contract_id: StorageContractId,
    pub host: Address,
    pub validator: Address,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub bytes_stored: u64,
    pub merkle_root: String,
    pub challenge_seed: String,
    #[serde(default)]
    pub samples: Vec<StorageProofSample>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedStorageProofReceipt {
    pub id: ReceiptId,
    pub body: StorageProofReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofBatch {
    pub contract_id: StorageContractId,
    pub receipts: Vec<SignedStorageProofReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainIsolationMode {
    OpaqueSandbox,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainOfferingStatus {
    PendingSetup,
    Active,
    Paused,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOfferingRecord {
    pub offering_id: DomainOfferingId,
    pub validator: Address,
    pub suffix: String,
    pub gateway_url: String,
    pub isolation_mode: DomainIsolationMode,
    pub status: DomainOfferingStatus,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainLeaseStatus {
    Active,
    Cancelled,
    Expired,
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainLeaseRecord {
    pub lease_id: DomainLeaseId,
    pub offering_id: DomainOfferingId,
    pub owner: Address,
    pub label: String,
    pub fqdn: String,
    pub target_contract_id: StorageContractId,
    pub prepaid_balance: u64,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_paid_at: DateTime<Utc>,
    pub status: DomainLeaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRouteResponse {
    pub chain_id: String,
    pub offering: DomainOfferingRecord,
    pub lease: DomainLeaseRecord,
    pub contract: StorageContractRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRecord {
    pub monitor_id: String,
    pub owner: Address,
    pub spec: MonitorSpec,
    pub budget_balance: u64,
    pub status: MonitorStatus,
    pub paused: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub next_slot_hint: Option<String>,
    pub last_observation_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionKind {
    Transfer {
        to: Address,
        amount: u64,
    },
    StorageTransfer {
        to: Address,
        amount: u64,
    },
    ComputeTransfer {
        to: Address,
        amount: u64,
    },
    DnsTransfer {
        to: Address,
        amount: u64,
    },
    HealthCheck {
        spec: HealthCheckSpec,
    },
    BrowserCheck {
        spec: BrowserCheckSpec,
    },
    ComputeJob {
        spec: ComputeJobSpec,
    },
    SwapLock {
        quote: SignedSwapQuote,
    },
    SwapCancel {
        quote_id: String,
    },
    SwapSettle {
        quote_id: String,
    },
    MonitorCreate {
        spec: MonitorSpec,
        initial_budget: u64,
    },
    MonitorUpdate {
        monitor_id: String,
        spec: MonitorSpec,
    },
    MonitorPause {
        monitor_id: String,
    },
    MonitorResume {
        monitor_id: String,
    },
    MonitorTopUp {
        monitor_id: String,
        amount: u64,
    },
    MonitorDelete {
        monitor_id: String,
    },
    StorageCreate {
        spec: StorageContractSpec,
        prepaid_balance: u64,
    },
    StorageTopUp {
        contract_id: StorageContractId,
        amount: u64,
    },
    StorageCancel {
        contract_id: StorageContractId,
    },
    DomainOfferingCreate {
        offering_id: DomainOfferingId,
        suffix: String,
        gateway_url: String,
    },
    DomainOfferingPause {
        offering_id: DomainOfferingId,
    },
    DomainOfferingResume {
        offering_id: DomainOfferingId,
    },
    DomainOfferingRetire {
        offering_id: DomainOfferingId,
    },
    DomainLeaseCreate {
        offering_id: DomainOfferingId,
        label: String,
        target_contract_id: StorageContractId,
        duration_secs: u64,
    },
    DomainLeaseRenew {
        lease_id: DomainLeaseId,
        duration_secs: u64,
    },
    DomainLeaseBind {
        lease_id: DomainLeaseId,
        target_contract_id: StorageContractId,
    },
    DomainLeaseCancel {
        lease_id: DomainLeaseId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBody {
    pub chain_id: String,
    pub nonce: u64,
    pub created_at: DateTime<Utc>,
    pub kind: TransactionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub hash: TxHash,
    pub signer: Address,
    pub body: TransactionBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResult {
    pub assertion: ResponseAssertion,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReceiptBody {
    pub chain_id: String,
    pub tx_hash: TxHash,
    pub request_id: String,
    pub executor: Address,
    pub observed_at: DateTime<Utc>,
    pub response_status: Option<u16>,
    pub latency_ms: u64,
    pub success: bool,
    pub assertion_results: Vec<AssertionResult>,
    #[serde(default)]
    pub response_headers: BTreeMap<String, String>,
    pub response_body_sample: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHealthReceipt {
    pub id: ReceiptId,
    pub body: HealthReceiptBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockApprovalBody {
    pub chain_id: String,
    pub height: u64,
    pub view: u64,
    pub previous_hash: BlockHash,
    pub block_hash: BlockHash,
    pub approver: Address,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlockApproval {
    pub id: ApprovalId,
    pub body: BlockApprovalBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHealthBatch {
    pub tx_hash: TxHash,
    pub receipts: Vec<SignedHealthReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    pub chain_id: String,
    pub height: u64,
    pub view: u64,
    pub previous_hash: BlockHash,
    pub proposer: Address,
    pub proposed_at: DateTime<Utc>,
    pub transactions: Vec<SignedTransaction>,
    #[serde(default)]
    pub health_batches: Vec<BlockHealthBatch>,
    #[serde(default)]
    pub browser_batches: Vec<BlockBrowserBatch>,
    #[serde(default)]
    pub compute_batches: Vec<BlockComputeBatch>,
    #[serde(default)]
    pub monitor_browser_batches: Vec<MonitorBrowserBatch>,
    #[serde(default)]
    pub heartbeat_observations: Vec<SignedHeartbeatObservation>,
    #[serde(default)]
    pub monitor_evaluations: Vec<MonitorEvaluation>,
    #[serde(default)]
    pub confirmation_batches: Vec<MonitorConfirmationBatch>,
    #[serde(default)]
    pub storage_proof_batches: Vec<StorageProofBatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlock {
    pub hash: BlockHash,
    pub body: BlockBody,
    pub signature: String,
    #[serde(default)]
    pub approvals: Vec<SignedBlockApproval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub treasury: Address,
    pub validators: Vec<Address>,
    #[serde(default = "default_chain_started_at")]
    pub chain_started_at: DateTime<Utc>,
    #[serde(default = "default_block_time_secs")]
    pub block_time_secs: u64,
    #[serde(default = "default_min_health_receipts")]
    pub min_health_receipts: usize,
    #[serde(default)]
    pub airdrops: BTreeMap<Address, u64>,
    #[serde(default)]
    pub storage_airdrops: BTreeMap<Address, u64>,
    #[serde(default)]
    pub compute_airdrops: BTreeMap<Address, u64>,
    #[serde(default)]
    pub dns_airdrops: BTreeMap<Address, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum NetworkMessage {
    Transaction(SignedTransaction),
    Receipt(SignedHealthReceipt),
    BrowserReceipt(SignedBrowserReceipt),
    ComputeReceipt(SignedComputeReceipt),
    HeartbeatObservation(SignedHeartbeatObservation),
    DelegatedProbeReceipt(SignedDelegatedProbeReceipt),
    StorageProofReceipt(SignedStorageProofReceipt),
    BlockApproval(SignedBlockApproval),
    Block(SignedBlock),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub address: Address,
    pub balance: u64,
    pub storage_balance: u64,
    pub compute_balance: u64,
    pub dns_balance: u64,
    pub nonce: u64,
    pub locked_balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub chain_id: String,
    pub height: u64,
    pub last_block_hash: BlockHash,
    pub accounts: Vec<AccountSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwapSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAsset {
    Usdc,
    Usdt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuoteRequest {
    pub wallet: Address,
    pub token_amount: u64,
    pub side: SwapSide,
    pub settlement_asset: SettlementAsset,
    pub adapter: Option<String>,
    #[serde(default = "default_swap_quote_ttl_secs")]
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuote {
    pub chain_id: String,
    pub quote_id: String,
    pub wallet: Address,
    pub adapter: String,
    pub side: SwapSide,
    pub settlement_asset: SettlementAsset,
    pub token_amount: u64,
    pub settlement_amount: u64,
    pub settlement_decimals: u8,
    pub expires_at: DateTime<Utc>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSwapQuote {
    #[serde(flatten)]
    pub quote: SwapQuote,
    pub quoted_by: Address,
    pub quoted_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapExecutionPlan {
    pub quote: SignedSwapQuote,
    pub steps: Vec<String>,
    pub follow_up_transfer_hint: Option<String>,
}

pub fn default_timeout_ms() -> u64 {
    3_000
}

pub fn default_block_time_secs() -> u64 {
    10
}

pub fn default_chain_started_at() -> DateTime<Utc> {
    Utc::now()
}

pub fn default_min_health_receipts() -> usize {
    2
}

pub fn default_swap_quote_ttl_secs() -> u64 {
    DEFAULT_SWAP_QUOTE_TTL_SECS
}

pub fn default_storage_chunk_size_bytes() -> u64 {
    DEFAULT_STORAGE_CHUNK_SIZE_BYTES
}

pub fn default_storage_proof_interval_secs() -> u64 {
    DEFAULT_STORAGE_PROOF_INTERVAL_SECS
}

pub fn default_storage_proof_sample_count() -> u16 {
    DEFAULT_STORAGE_PROOF_SAMPLE_COUNT
}

pub fn default_storage_reward_rate_per_quantum_second() -> u64 {
    STORAGE_REWARD_PER_QUANTUM_SECOND
}

pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn compute_hash<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

pub fn validate_block_body_limits(body: &BlockBody) -> Result<()> {
    if body.transactions.len() > MAX_BLOCK_TRANSACTIONS {
        bail!("block exceeds the maximum transaction count");
    }
    if body.confirmation_batches.len() > MAX_CONFIRMATION_BATCHES {
        bail!("block exceeds the maximum confirmation batch count");
    }
    let size = canonical_bytes(body)?.len();
    if size > MAX_BLOCK_BODY_BYTES {
        bail!("block exceeds the maximum serialized size");
    }
    Ok(())
}

pub fn parse_amount(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("amount cannot be empty");
    }

    let negative = trimmed.starts_with('-');
    if negative {
        bail!("amount cannot be negative");
    }

    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() > 2 {
        bail!("invalid amount format");
    }

    let whole: u64 = parts[0].parse()?;
    let fractional = if let Some(fraction) = parts.get(1) {
        if fraction.len() > TOKEN_DECIMALS as usize {
            bail!("amount supports at most {TOKEN_DECIMALS} decimal places");
        }

        let padded = format!("{fraction:0<width$}", width = TOKEN_DECIMALS as usize);
        padded.parse::<u64>()?
    } else {
        0
    };

    whole
        .checked_mul(MICRO_HT)
        .and_then(|value| value.checked_add(fractional))
        .ok_or_else(|| anyhow!("amount overflow"))
}

pub fn format_amount(amount: u64) -> String {
    let whole = amount / MICRO_HT;
    let fraction = amount % MICRO_HT;
    if fraction == 0 {
        return whole.to_string();
    }

    let mut fraction_str = format!("{fraction:0>width$}", width = TOKEN_DECIMALS as usize);
    while fraction_str.ends_with('0') {
        fraction_str.pop();
    }
    format!("{whole}.{fraction_str}")
}

pub fn health_check_cost(spec: &HealthCheckSpec) -> Result<u64> {
    validate_health_check_spec(spec)?;

    let mut total = HEALTH_CHECK_BASE_COST;
    if spec.timeout_ms > INCLUDED_HEALTH_TIMEOUT_MS {
        let extra_timeout_ms = spec.timeout_ms - INCLUDED_HEALTH_TIMEOUT_MS;
        let steps = extra_timeout_ms.div_ceil(HEALTH_TIMEOUT_SURCHARGE_STEP_MS);
        total = total
            .checked_add(steps * HEALTH_TIMEOUT_SURCHARGE_STEP_COST)
            .ok_or_else(|| anyhow!("health check cost overflow"))?;
    }

    let complexity_units = spec.headers.len() + spec.query.len() + spec.assertions.len();
    if complexity_units > INCLUDED_HEALTH_COMPLEXITY_UNITS {
        let extra_units = (complexity_units - INCLUDED_HEALTH_COMPLEXITY_UNITS) as u64;
        total = total
            .checked_add(extra_units * HEALTH_COMPLEXITY_SURCHARGE_UNIT_COST)
            .ok_or_else(|| anyhow!("health check cost overflow"))?;
    }

    if let Some(body_json) = &spec.body_json {
        let body_bytes = serde_json::to_vec(body_json)?.len();
        if body_bytes > INCLUDED_HEALTH_BODY_BYTES {
            let extra_body_bytes = body_bytes - INCLUDED_HEALTH_BODY_BYTES;
            let body_steps = extra_body_bytes.div_ceil(1_024) as u64;
            total = total
                .checked_add(body_steps * HEALTH_BODY_SURCHARGE_PER_KIB)
                .ok_or_else(|| anyhow!("health check cost overflow"))?;
        }
    }

    Ok(total)
}

pub fn storage_chunk_count(spec: &StorageContractSpec) -> u64 {
    spec.size_bytes.div_ceil(spec.chunk_size_bytes)
}

pub fn storage_reward_for_elapsed(
    size_bytes: u64,
    elapsed_secs: u64,
    reward_rate_per_64mib_second: u64,
) -> Result<u64> {
    let numerator = (size_bytes as u128)
        .checked_mul(elapsed_secs as u128)
        .and_then(|value| value.checked_mul(reward_rate_per_64mib_second as u128))
        .ok_or_else(|| anyhow!("storage reward overflow"))?;
    let reward = numerator / STORAGE_BILLING_QUANTUM_BYTES as u128;
    u64::try_from(reward).map_err(|_| anyhow!("storage reward overflow"))
}

pub fn dns_lease_cost(duration_secs: u64) -> Result<u64> {
    if duration_secs == 0 || duration_secs > MAX_DOMAIN_LEASE_DURATION_SECS {
        bail!("domain lease duration_secs is invalid");
    }
    duration_secs
        .checked_mul(DNS_LEASE_COST_PER_SUBDOMAIN_SECOND)
        .ok_or_else(|| anyhow!("domain lease cost overflow"))
}

pub fn domain_fqdn(label: &str, suffix: &str) -> Result<String> {
    validate_domain_label(label)?;
    validate_domain_suffix(suffix)?;
    Ok(format!("{label}.{suffix}"))
}

pub fn storage_challenge_seed(
    chain_id: &str,
    contract_id: &str,
    previous_block_hash: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    merkle_root: &str,
) -> Result<String> {
    compute_hash(&(
        "storage-proof-v1",
        chain_id.to_string(),
        contract_id.to_string(),
        previous_block_hash.to_string(),
        window_start,
        window_end,
        merkle_root.to_string(),
    ))
}

pub fn storage_challenge_indices(
    challenge_seed: &str,
    chunk_count: u64,
    sample_count: u16,
) -> Result<Vec<u64>> {
    if chunk_count == 0 {
        bail!("storage challenge requires at least one chunk");
    }
    if sample_count == 0 {
        bail!("storage challenge sample_count must be greater than zero");
    }
    if u64::from(sample_count) > chunk_count {
        bail!("storage challenge sample_count cannot exceed chunk count");
    }

    let mut indices = Vec::with_capacity(sample_count as usize);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0u64;
    while indices.len() < sample_count as usize {
        let mut hasher = Sha256::new();
        hasher.update(challenge_seed.as_bytes());
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&digest[..8]);
        let index = u64::from_be_bytes(raw) % chunk_count;
        if seen.insert(index) {
            indices.push(index);
        }
        counter += 1;
    }
    Ok(indices)
}

pub fn confirmation_probe_cost(batch: &MonitorConfirmationBatch) -> Result<u64> {
    let mut total = 0u64;
    for receipt in &batch.validator_receipts {
        let cost = if receipt.body.success {
            HEALTH_CHECK_BASE_COST
        } else {
            HEALTH_CHECK_BASE_COST + HEALTH_TIMEOUT_SURCHARGE_STEP_COST
        };
        total = total
            .checked_add(cost)
            .ok_or_else(|| anyhow!("confirmation probe cost overflow"))?;
    }
    for _ in &batch.delegated_receipts {
        total = total
            .checked_add(HEALTH_CHECK_BASE_COST / 2)
            .ok_or_else(|| anyhow!("confirmation probe cost overflow"))?;
    }
    Ok(total)
}

pub fn required_probe_fanout_count(fanout: &ProbeFanoutPolicy, provider_count: usize) -> usize {
    match fanout {
        ProbeFanoutPolicy::OnePerValidator | ProbeFanoutPolicy::AllValidators => provider_count,
        ProbeFanoutPolicy::KValidatorsMin { count }
        | ProbeFanoutPolicy::KAgentsWithRegionDiversity { count } => (*count).min(provider_count),
    }
}

pub fn required_monitor_confirmation_receipts(policy: &MissPolicy, provider_count: usize) -> usize {
    match policy {
        MissPolicy::RecordOnly => 0,
        MissPolicy::ConfirmWithValidators { fanout }
        | MissPolicy::ConfirmWithDelegatedAgents { fanout, .. } => {
            required_probe_fanout_count(fanout, provider_count)
        }
    }
}

pub fn monitor_browser_slot_cost(package: &BrowserJourneyPackage) -> Result<u64> {
    browser_check_cost(&BrowserCheckSpec {
        request_id: "scheduled-monitor-slot".to_string(),
        package: package.clone(),
    })
}

pub fn monitor_minimum_slot_balance(spec: &MonitorSpec) -> Result<u64> {
    match &spec.pathway {
        MonitorPathway::Heartbeat { .. } => Ok(MONITOR_SLOT_RESERVATION_FEE),
        MonitorPathway::Browser { package } => monitor_browser_slot_cost(package),
    }
}

pub fn required_delegated_probe_receipts(
    policy: &MissPolicy,
    assigned_validator_count: usize,
) -> usize {
    match policy {
        MissPolicy::RecordOnly | MissPolicy::ConfirmWithValidators { .. } => 0,
        MissPolicy::ConfirmWithDelegatedAgents {
            fanout,
            require_region_diversity,
        } => {
            let base = match fanout {
                ProbeFanoutPolicy::OnePerValidator | ProbeFanoutPolicy::AllValidators => {
                    assigned_validator_count
                }
                ProbeFanoutPolicy::KValidatorsMin { .. } => assigned_validator_count,
                ProbeFanoutPolicy::KAgentsWithRegionDiversity { count } => *count,
            };
            base.max(*require_region_diversity)
                .max(assigned_validator_count)
        }
    }
}

pub fn required_local_agent_receipts(
    policy: &MissPolicy,
    assigned_validator_count: usize,
    available_agents: usize,
) -> usize {
    if available_agents == 0 || assigned_validator_count == 0 {
        return 0;
    }
    match policy {
        MissPolicy::RecordOnly | MissPolicy::ConfirmWithValidators { .. } => 0,
        MissPolicy::ConfirmWithDelegatedAgents {
            require_region_diversity,
            ..
        } => {
            let total_agents = required_delegated_probe_receipts(policy, assigned_validator_count);
            let per_validator = total_agents.div_ceil(assigned_validator_count);
            let region_floor = require_region_diversity.div_ceil(assigned_validator_count);
            per_validator.max(region_floor).max(1).min(available_agents)
        }
    }
}

pub fn validate_swap_quote_request(request: &SwapQuoteRequest) -> Result<()> {
    if request.wallet.trim().is_empty() {
        bail!("swap quote wallet cannot be empty");
    }
    if request.token_amount == 0 {
        bail!("swap quote token_amount must be greater than zero");
    }
    if request.ttl_secs == 0 || request.ttl_secs > MAX_SWAP_QUOTE_TTL_SECS {
        bail!("swap quote ttl_secs must be between 1 and {MAX_SWAP_QUOTE_TTL_SECS} seconds");
    }
    Ok(())
}

pub fn validate_health_check_spec(spec: &HealthCheckSpec) -> Result<()> {
    if spec.request_id.trim().is_empty() {
        bail!("health check request_id cannot be empty");
    }
    if spec.url.is_empty() {
        bail!("health check url cannot be empty");
    }
    if spec.url.len() > MAX_HEALTH_URL_LENGTH {
        bail!("health check url exceeds maximum length");
    }
    if spec.timeout_ms < MIN_TIMEOUT_MS || spec.timeout_ms > MAX_TIMEOUT_MS {
        bail!("health check timeout must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS} ms");
    }
    if spec.headers.len() > MAX_HEALTH_HEADERS {
        bail!("health check has too many headers");
    }
    if spec.query.len() > MAX_HEALTH_QUERY_PARAMS {
        bail!("health check has too many query parameters");
    }
    if spec.assertions.len() > MAX_HEALTH_ASSERTIONS {
        bail!("health check has too many assertions");
    }

    let url = Url::parse(&spec.url)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => bail!("health check url must use http or https"),
    }
    if url.host_str().is_none() {
        bail!("health check url must include a host");
    }

    for (name, value) in &spec.headers {
        if name.is_empty() || name.len() > MAX_HEADER_NAME_BYTES {
            bail!("health check header name is invalid");
        }
        if value.len() > MAX_HEADER_VALUE_BYTES {
            bail!("health check header value exceeds maximum length");
        }
    }
    for (key, value) in &spec.query {
        if key.is_empty() || key.len() > MAX_QUERY_KEY_BYTES {
            bail!("health check query key is invalid");
        }
        if value.len() > MAX_QUERY_VALUE_BYTES {
            bail!("health check query value exceeds maximum length");
        }
    }
    for assertion in &spec.assertions {
        match assertion {
            ResponseAssertion::JsonFieldExists { path }
            | ResponseAssertion::BodyContains { text: path } => {
                if path.is_empty() || path.len() > MAX_ASSERTION_TEXT_BYTES {
                    bail!("health check assertion text exceeds maximum length");
                }
            }
            ResponseAssertion::JsonFieldEquals { path, value } => {
                if path.is_empty() || path.len() > MAX_ASSERTION_TEXT_BYTES {
                    bail!("health check assertion path exceeds maximum length");
                }
                if serde_json::to_vec(value)?.len() > MAX_JSON_BODY_BYTES {
                    bail!("health check assertion value exceeds maximum size");
                }
            }
            ResponseAssertion::HeaderEquals { name, value } => {
                if name.is_empty() || name.len() > MAX_HEADER_NAME_BYTES {
                    bail!("health check assertion header name is invalid");
                }
                if value.len() > MAX_HEADER_VALUE_BYTES {
                    bail!("health check assertion header value exceeds maximum length");
                }
            }
        }
    }

    if !matches!(spec.method, HealthHttpMethod::Post) && spec.body_json.is_some() {
        bail!("health check body_json is only supported for POST requests");
    }
    if let Some(body) = &spec.body_json
        && serde_json::to_vec(body)?.len() > MAX_JSON_BODY_BYTES
    {
        bail!("health check body_json exceeds maximum size");
    }
    if let Some(status) = spec.expected_status
        && !(100..=599).contains(&status)
    {
        bail!("health check expected_status must be a valid HTTP status");
    }

    Ok(())
}

pub fn validate_monitor_spec(spec: &MonitorSpec) -> Result<()> {
    if spec.monitor_id.trim().is_empty() || spec.monitor_id.len() > MAX_MONITOR_ID_BYTES {
        bail!("monitor_id is invalid");
    }
    if let Some(slug) = &spec.slug
        && (slug.trim().is_empty() || slug.len() > MAX_MONITOR_SLUG_BYTES)
    {
        bail!("monitor slug is invalid");
    }
    match &spec.schedule {
        ScheduleSpec::Interval { every_secs, .. } => {
            if *every_secs < MONITOR_MIN_INTERVAL_SECS {
                bail!("monitor interval is too short");
            }
        }
        ScheduleSpec::CronUtc { expr } => {
            if expr.trim().is_empty() {
                bail!("monitor cron expression cannot be empty");
            }
        }
    }
    if spec.grace_secs > MONITOR_MAX_GRACE_SECS {
        bail!("monitor grace period is too large");
    }
    match &spec.pathway {
        MonitorPathway::Heartbeat {
            ping_auth,
            signal_policy,
            miss_policy,
            confirmation_probe,
        } => {
            validate_heartbeat_auth(ping_auth)?;
            validate_signal_policy(signal_policy)?;
            validate_miss_policy(miss_policy)?;
            if let Some(probe) = confirmation_probe {
                validate_health_check_spec(probe)?;
            }
        }
        MonitorPathway::Browser { package } => {
            crate::browser::validate_browser_journey_package(package)?;
            let _ = monitor_browser_slot_cost(package)?;
        }
    }
    if let Some(policy_id) = &spec.notification_policy_id
        && (policy_id.trim().is_empty() || policy_id.len() > MAX_NOTIFICATION_POLICY_ID_BYTES)
    {
        bail!("notification policy id is invalid");
    }
    match spec.log_capture {
        LogCapturePolicy::None => {}
        LogCapturePolicy::CaptureText { max_bytes } => {
            if max_bytes == 0 || max_bytes > MAX_LOG_CAPTURE_BYTES {
                bail!("log capture size is invalid");
            }
        }
    }
    if spec.tags.len() > MAX_MONITOR_TAGS {
        bail!("monitor has too many tags");
    }
    for (key, value) in &spec.tags {
        if key.trim().is_empty() || key.len() > MAX_MONITOR_TAG_KEY_BYTES {
            bail!("monitor tag key is invalid");
        }
        if value.len() > MAX_MONITOR_TAG_VALUE_BYTES {
            bail!("monitor tag value is invalid");
        }
    }
    Ok(())
}

pub fn validate_storage_contract_spec(spec: &StorageContractSpec) -> Result<()> {
    if spec.contract_id.trim().is_empty() || spec.contract_id.len() > MAX_STORAGE_CONTRACT_ID_BYTES
    {
        bail!("storage contract_id is invalid");
    }
    if spec.host.trim().is_empty() {
        bail!("storage host cannot be empty");
    }
    if spec.size_bytes == 0 || spec.size_bytes > MAX_STORAGE_CONTRACT_BYTES {
        bail!("storage size_bytes is invalid");
    }
    if spec.chunk_size_bytes < MIN_STORAGE_CHUNK_SIZE_BYTES
        || spec.chunk_size_bytes > MAX_STORAGE_CHUNK_SIZE_BYTES
    {
        bail!("storage chunk_size_bytes is invalid");
    }
    if spec.duration_secs == 0 || spec.duration_secs > MAX_STORAGE_DURATION_SECS {
        bail!("storage duration_secs is invalid");
    }
    if spec.proof_interval_secs == 0
        || spec.proof_interval_secs > MAX_STORAGE_PROOF_INTERVAL_SECS
        || spec.proof_interval_secs > spec.duration_secs
    {
        bail!("storage proof_interval_secs is invalid");
    }
    if spec.proof_sample_count == 0 || spec.proof_sample_count > MAX_STORAGE_PROOF_SAMPLE_COUNT {
        bail!("storage proof_sample_count is invalid");
    }
    if u64::from(spec.proof_sample_count) > storage_chunk_count(spec) {
        bail!("storage proof_sample_count cannot exceed the number of chunks");
    }
    if spec.reward_rate_per_64mib_second == 0 {
        bail!("storage reward rate must be greater than zero");
    }
    validate_sha256_hex(&spec.merkle_root, "storage merkle_root")?;

    match &spec.mode {
        StorageMode::Encrypted => {}
        StorageMode::PublicRaw { manifest } => {
            if let Some(manifest) = manifest {
                validate_static_site_manifest(manifest)?;
            }
        }
    }

    Ok(())
}

pub fn validate_domain_offering_input(
    offering_id: &str,
    suffix: &str,
    gateway_url: &str,
) -> Result<()> {
    if offering_id.trim().is_empty() || offering_id.len() > MAX_DOMAIN_OFFERING_ID_BYTES {
        bail!("domain offering_id is invalid");
    }
    validate_domain_suffix(suffix)?;
    if gateway_url.trim().is_empty() || gateway_url.len() > MAX_DOMAIN_GATEWAY_URL_BYTES {
        bail!("domain gateway_url is invalid");
    }
    let url = Url::parse(gateway_url)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => bail!("domain gateway_url must use http or https"),
    }
    if url.host_str().is_none() {
        bail!("domain gateway_url must include a host");
    }
    Ok(())
}

pub fn validate_domain_suffix(suffix: &str) -> Result<()> {
    if suffix.trim().is_empty() || suffix.len() > MAX_DOMAIN_SUFFIX_BYTES {
        bail!("domain suffix is invalid");
    }
    if suffix != suffix.to_ascii_lowercase()
        || suffix.starts_with('.')
        || suffix.ends_with('.')
        || suffix.contains("..")
        || suffix.contains('*')
        || suffix.contains('/')
        || suffix.contains('\\')
    {
        bail!("domain suffix is invalid");
    }
    if !suffix.starts_with("pages.") {
        bail!("domain suffix must start with pages.");
    }
    let labels = suffix.split('.').collect::<Vec<_>>();
    if labels.len() < 3 {
        bail!("domain suffix must be pages.<validator-domain>");
    }
    for label in labels {
        validate_dns_label(label, false)?;
    }
    Ok(())
}

pub fn validate_domain_label(label: &str) -> Result<()> {
    validate_dns_label(label, true)?;
    match label {
        "www" | "api" | "admin" | "mail" | "ns" | "dns" | "gateway" | "status" => {
            bail!("domain label is reserved")
        }
        _ => Ok(()),
    }
}

fn validate_dns_label(label: &str, leased_label: bool) -> Result<()> {
    if label.is_empty() || label.len() > MAX_DOMAIN_LABEL_BYTES {
        bail!("domain label is invalid");
    }
    if label != label.to_ascii_lowercase() {
        bail!("domain label must be lowercase ASCII");
    }
    let bytes = label.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        bail!("domain label cannot start or end with hyphen");
    }
    if leased_label && label.contains('.') {
        bail!("domain lease label must be a single DNS label");
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        bail!("domain label may only contain a-z, 0-9, and hyphen");
    }
    Ok(())
}

pub fn validate_storage_proof_sample(sample: &StorageProofSample, merkle_root: &str) -> Result<()> {
    validate_sha256_hex(&sample.chunk_hash, "storage proof chunk_hash")?;
    if sample.proof.len() > MAX_STORAGE_MERKLE_PROOF_DEPTH {
        bail!("storage merkle proof is too deep");
    }
    let mut current = decode_sha256_hex(&sample.chunk_hash, "storage proof chunk_hash")?;
    for node in &sample.proof {
        let sibling = decode_sha256_hex(&node.hash, "storage merkle proof node")?;
        let mut hasher = Sha256::new();
        match node.side {
            MerkleProofSide::Left => {
                hasher.update(sibling);
                hasher.update(current);
            }
            MerkleProofSide::Right => {
                hasher.update(current);
                hasher.update(sibling);
            }
        }
        current = hasher.finalize().into();
    }
    if hex::encode(current) != merkle_root {
        bail!("storage proof sample does not resolve to the contract merkle root");
    }
    Ok(())
}

fn validate_static_site_manifest(manifest: &StaticSiteManifest) -> Result<()> {
    if manifest.index_path.trim().is_empty()
        || manifest.index_path.len() > MAX_STORAGE_MANIFEST_PATH_BYTES
        || manifest.index_path.contains("..")
        || manifest.index_path.starts_with('/')
    {
        bail!("static site index_path is invalid");
    }
    if let Some(hash) = &manifest.critical_prefix_hash {
        validate_sha256_hex(hash, "static site critical_prefix_hash")?;
    }
    if let Some(bytes) = manifest.critical_prefix_bytes
        && bytes > MAX_STATIC_SITE_CRITICAL_PREFIX_BYTES
    {
        bail!(
            "static site critical_prefix_bytes must fit within the first {} bytes",
            MAX_STATIC_SITE_CRITICAL_PREFIX_BYTES
        );
    }
    if manifest.content_types.len() > MAX_STORAGE_MANIFEST_CONTENT_TYPES {
        bail!("static site manifest has too many content type overrides");
    }
    for (path, content_type) in &manifest.content_types {
        if path.trim().is_empty()
            || path.len() > MAX_STORAGE_MANIFEST_PATH_BYTES
            || path.contains("..")
            || path.starts_with('/')
        {
            bail!("static site content type path is invalid");
        }
        if content_type.trim().is_empty() || content_type.len() > MAX_STORAGE_CONTENT_TYPE_BYTES {
            bail!("static site content type value is invalid");
        }
    }
    Ok(())
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<()> {
    let _ = decode_sha256_hex(value, label)?;
    Ok(())
}

fn decode_sha256_hex(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("{label} must be a 32-byte hex digest");
    }
    let bytes = hex::decode(value).map_err(|_| anyhow!("{label} must be valid hex"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be a 32-byte hex digest"))?;
    Ok(array)
}

fn validate_heartbeat_auth(auth: &HeartbeatAuth) -> Result<()> {
    match auth {
        HeartbeatAuth::SecretUrl { token_hash } => {
            if token_hash.trim().is_empty() {
                bail!("token hash cannot be empty");
            }
        }
        HeartbeatAuth::DelegatedKey { key_id, public_key } => {
            if key_id.trim().is_empty() || key_id.len() > MAX_MONITOR_ID_BYTES {
                bail!("heartbeat key_id is invalid");
            }
            if public_key.trim().is_empty() {
                bail!("heartbeat public_key cannot be empty");
            }
        }
        HeartbeatAuth::Dual {
            token_hash,
            key_id,
            public_key,
        } => {
            if token_hash.trim().is_empty() {
                bail!("token hash cannot be empty");
            }
            if key_id.trim().is_empty() || key_id.len() > MAX_MONITOR_ID_BYTES {
                bail!("heartbeat key_id is invalid");
            }
            if public_key.trim().is_empty() {
                bail!("heartbeat public_key cannot be empty");
            }
        }
    }
    Ok(())
}

fn validate_signal_policy(policy: &SignalPolicy) -> Result<()> {
    match policy {
        SignalPolicy::SuccessOnly => Ok(()),
        SignalPolicy::StartAndSuccess { run_timeout_secs }
        | SignalPolicy::StartSuccessFail { run_timeout_secs } => {
            if *run_timeout_secs == 0 {
                bail!("run_timeout_secs must be greater than zero");
            }
            Ok(())
        }
    }
}

fn validate_miss_policy(policy: &MissPolicy) -> Result<()> {
    match policy {
        MissPolicy::RecordOnly => Ok(()),
        MissPolicy::ConfirmWithValidators { fanout } => validate_probe_fanout(fanout),
        MissPolicy::ConfirmWithDelegatedAgents {
            fanout,
            require_region_diversity,
        } => {
            if *require_region_diversity == 0 {
                bail!("require_region_diversity must be greater than zero");
            }
            validate_probe_fanout(fanout)
        }
    }
}

fn validate_probe_fanout(fanout: &ProbeFanoutPolicy) -> Result<()> {
    match fanout {
        ProbeFanoutPolicy::OnePerValidator | ProbeFanoutPolicy::AllValidators => Ok(()),
        ProbeFanoutPolicy::KValidatorsMin { count }
        | ProbeFanoutPolicy::KAgentsWithRegionDiversity { count } => {
            if *count == 0 {
                bail!("probe fanout count must be greater than zero");
            }
            Ok(())
        }
    }
}

pub fn schedule_next_slot_start(
    schedule: &ScheduleSpec,
    after: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    match schedule {
        ScheduleSpec::Interval {
            every_secs,
            anchor_at,
        } => {
            if after <= *anchor_at {
                return Ok(*anchor_at);
            }
            let elapsed = after.signed_duration_since(*anchor_at).num_seconds();
            let step = *every_secs as i64;
            let next_multiple = ((elapsed / step) + 1) * step;
            Ok(*anchor_at + chrono::Duration::seconds(next_multiple))
        }
        ScheduleSpec::CronUtc { expr } => {
            let schedule = cron::Schedule::from_str(expr)
                .map_err(|error| anyhow!("invalid cron expression: {error}"))?;
            schedule
                .after(&after)
                .next()
                .ok_or_else(|| anyhow!("cron schedule does not produce future slots"))
        }
    }
}

pub fn schedule_current_slot_start(
    schedule: &ScheduleSpec,
    at: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    match schedule {
        ScheduleSpec::Interval {
            every_secs,
            anchor_at,
        } => {
            if at <= *anchor_at {
                return Ok(*anchor_at);
            }
            let elapsed = at.signed_duration_since(*anchor_at).num_seconds();
            let step = *every_secs as i64;
            let current_multiple = (elapsed / step) * step;
            Ok(*anchor_at + chrono::Duration::seconds(current_multiple))
        }
        ScheduleSpec::CronUtc { expr } => {
            let schedule = cron::Schedule::from_str(expr)
                .map_err(|error| anyhow!("invalid cron expression: {error}"))?;
            let mut previous = None;
            for candidate in schedule.after(&(at - chrono::Duration::days(366))) {
                if candidate > at {
                    break;
                }
                previous = Some(candidate);
            }
            previous.ok_or_else(|| anyhow!("cron schedule does not produce a current slot"))
        }
    }
}

pub fn slot_key_for_time(schedule: &ScheduleSpec, at: DateTime<Utc>) -> Result<String> {
    Ok(schedule_current_slot_start(schedule, at)?.to_rfc3339())
}

pub fn monitor_browser_tx_hash(monitor_id: &str, slot_key: &str) -> Result<String> {
    compute_hash(&(
        monitor_id.to_string(),
        slot_key.to_string(),
        "monitor-browser",
    ))
}

pub fn monitor_browser_request_id(monitor_id: &str, slot_key: &str) -> String {
    format!("monitor-browser:{monitor_id}:{slot_key}")
}

pub fn slot_deadline(slot_started_at: DateTime<Utc>, grace_secs: u64) -> DateTime<Utc> {
    slot_started_at + chrono::Duration::seconds(grace_secs as i64)
}

pub fn hash_secret_token(token: &str) -> Result<String> {
    if token.trim().is_empty() {
        bail!("token cannot be empty");
    }
    compute_hash(&token)
}

pub fn truncate_capture(input: &str, limit: usize) -> String {
    let bytes = input.as_bytes();
    if bytes.len() <= limit {
        return input.to_string();
    }
    String::from_utf8_lossy(&bytes[..limit]).to_string()
}

pub fn canonical_heartbeat_client_message(
    monitor_id: &str,
    signal: HeartbeatSignal,
    timestamp: DateTime<Utc>,
    nonce: &str,
    body_sha256: Option<&str>,
) -> Result<Vec<u8>> {
    canonical_bytes(&(
        monitor_id.to_string(),
        signal,
        timestamp,
        nonce.to_string(),
        body_sha256.map(ToOwned::to_owned),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn health_check_cost_scales_for_expensive_specs() {
        let simple = HealthCheckSpec {
            request_id: "simple".into(),
            url: "https://example.com/health".into(),
            method: HealthHttpMethod::Get,
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            timeout_ms: 3_000,
            expected_status: Some(200),
            assertions: Vec::new(),
            body_json: None,
            allow_insecure_http: false,
            allow_private_targets: false,
        };
        let expensive = HealthCheckSpec {
            request_id: "expensive".into(),
            url: "https://example.com/health".into(),
            method: HealthHttpMethod::Post,
            headers: (0..10)
                .map(|index| (format!("x-{index}"), format!("value-{index}")))
                .collect(),
            query: BTreeMap::new(),
            timeout_ms: 7_000,
            expected_status: Some(200),
            assertions: vec![
                ResponseAssertion::JsonFieldExists {
                    path: "service.version".into(),
                };
                4
            ],
            body_json: Some(json!({
                "payload": "x".repeat(2_048),
            })),
            allow_insecure_http: false,
            allow_private_targets: false,
        };

        assert_eq!(health_check_cost(&simple).unwrap(), HEALTH_CHECK_BASE_COST);
        assert!(health_check_cost(&expensive).unwrap() > HEALTH_CHECK_BASE_COST);
    }

    #[test]
    fn block_body_limits_reject_oversized_block() {
        let body = BlockBody {
            chain_id: "test".into(),
            height: 1,
            view: 0,
            previous_hash: "genesis".into(),
            proposer: "validator".into(),
            proposed_at: Utc::now(),
            transactions: Vec::new(),
            health_batches: Vec::new(),
            browser_batches: Vec::new(),
            compute_batches: Vec::new(),
            monitor_browser_batches: Vec::new(),
            heartbeat_observations: Vec::new(),
            monitor_evaluations: Vec::new(),
            confirmation_batches: Vec::new(),
            storage_proof_batches: Vec::new(),
        };
        validate_block_body_limits(&body).unwrap();
    }
}
