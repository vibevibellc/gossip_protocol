use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path as AxumPath, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures::future::join_all;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{Mutex, RwLock},
    time::{interval, sleep},
};
use tracing::{error, info, warn};

use crate::{
    agent::{AgentBrowserResponse, AgentComputeResponse, AgentConfirmationResponse},
    browser::{
        BlockBrowserBatch, BrowserAgentLeaseBody, BrowserCheckSpec, BrowserReceiptBody,
        BrowserRunnerConfig, SignedBrowserAgentLease, SignedBrowserReceipt,
        SignedDelegatedBrowserReceipt, execute_browser_check,
    },
    compute::{
        BlockComputeBatch, ComputeJobSpec, ComputeReceiptBody, ComputeShardLeaseBody,
        SignedComputeReceipt, SignedComputeShardLease, compute_job_hash, reduce_compute_outputs,
    },
    compute_sandbox::{compute_artifact_path, execute_compute_shard_isolated},
    health::{HealthExecution, execute_health_check},
    ledger::{
        ChainState, FinalizedBrowserCheck, FinalizedComputeJob, FinalizedHealthCheck,
        PendingSwapLock,
    },
    protocol::{
        Address, AlertFact, BlockApprovalBody, BlockBody, DomainRouteResponse, HealthCheckSpec,
        HealthReceiptBody, HeartbeatAuth, HeartbeatAuthMode, HeartbeatObservationBody,
        HeartbeatSignal, LedgerSnapshot, LogCapturePolicy, MAX_BLOCK_TRANSACTIONS,
        MAX_HEARTBEAT_NONCE_BYTES, MissPolicy, MonitorBrowserBatch, MonitorConfirmationBatch,
        MonitorEvaluation, MonitorEvaluationKind, MonitorRecord, MonitorSlotRecord,
        MonitorSlotStatus, ProbeAgentLeaseBody, SignalPolicy, SignedBlock, SignedBlockApproval,
        SignedDelegatedProbeReceipt, SignedHealthReceipt, SignedHeartbeatObservation,
        SignedProbeAgentLease, SignedStorageProofReceipt, SignedSwapQuote, SignedTransaction,
        StorageContractRecord, StorageProofBatch, SwapExecutionPlan, SwapQuoteRequest,
        TransactionKind, canonical_heartbeat_client_message, compute_hash, hash_secret_token,
        monitor_browser_request_id, monitor_browser_slot_cost, monitor_browser_tx_hash,
        monitor_minimum_slot_balance, required_delegated_probe_receipts,
        required_local_agent_receipts, required_monitor_confirmation_receipts,
        schedule_current_slot_start, schedule_next_slot_start, slot_deadline, truncate_capture,
        validate_block_body_limits,
    },
    scheduler::{RoundRobinDomain, RoundRobinPlan},
    swap::SwapRegistry,
    wallet::{
        Wallet, verify_browser_agent_lease, verify_compute_shard_lease,
        verify_delegated_browser_receipt, verify_delegated_compute_shard_receipt,
        verify_delegated_probe_receipt, verify_heartbeat_observation,
    },
};

const PROPOSAL_STAGGER_MS: u64 = 250;
const PEER_SYNC_INTERVAL_SECS: u64 = 1;
const MAX_CLIENT_CLOCK_SKEW_SECS: i64 = 300;
const CLIENT_NONCE_RETENTION_SECS: i64 = 86_400;

type FinalizedRecords = (
    Vec<FinalizedHealthCheck>,
    Vec<FinalizedBrowserCheck>,
    Vec<FinalizedComputeJob>,
);

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bind_addr: SocketAddr,
    pub wallet_path: PathBuf,
    pub genesis_path: PathBuf,
    pub state_dir: PathBuf,
    pub peers: Vec<String>,
    pub swap_config_path: Option<PathBuf>,
    pub notification_policies_path: Option<PathBuf>,
    pub probe_agents_path: Option<PathBuf>,
    pub browser_runner_program: Option<PathBuf>,
    pub browser_runner_args: Vec<String>,
    pub browser_cache_dir: Option<PathBuf>,
    pub browser_secret_store_path: Option<PathBuf>,
    pub control_api_token: Option<String>,
    pub gossip_api_token: Option<String>,
    pub wallet_passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNodeState {
    pub chain: ChainState,
    #[serde(skip_serializing, default)]
    pub finalized_blocks: BTreeMap<u64, SignedBlock>,
    #[serde(default)]
    pub mempool: BTreeMap<String, SignedTransaction>,
    #[serde(default)]
    pub receipts: BTreeMap<String, Vec<SignedHealthReceipt>>,
    #[serde(default)]
    pub browser_receipts: BTreeMap<String, Vec<SignedBrowserReceipt>>,
    #[serde(default)]
    pub compute_receipts: BTreeMap<String, Vec<SignedComputeReceipt>>,
    #[serde(default)]
    pub storage_proof_receipts: BTreeMap<String, Vec<SignedStorageProofReceipt>>,
    #[serde(default)]
    pub heartbeat_observations: BTreeMap<String, Vec<SignedHeartbeatObservation>>,
    #[serde(default)]
    pub heartbeat_client_nonces: BTreeMap<String, DateTime<Utc>>,
    #[serde(default)]
    pub block_approvals: BTreeMap<String, SignedBlockApproval>,
    #[serde(default)]
    pub delivered_alerts: BTreeMap<String, DateTime<Utc>>,
    #[serde(default)]
    pub active_view: u64,
    #[serde(default = "default_view_started_at")]
    pub view_started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum PersistedJournalEvent {
    TransactionAccepted {
        tx: SignedTransaction,
    },
    ReceiptAccepted {
        receipt: SignedHealthReceipt,
    },
    BrowserReceiptAccepted {
        receipt: SignedBrowserReceipt,
    },
    ComputeReceiptAccepted {
        receipt: SignedComputeReceipt,
    },
    StorageProofReceiptAccepted {
        receipt: SignedStorageProofReceipt,
    },
    HeartbeatObservationAccepted {
        observation: SignedHeartbeatObservation,
    },
    ApprovalStored {
        approval: SignedBlockApproval,
    },
    ViewAdvanced {
        active_view: u64,
        view_started_at: DateTime<Utc>,
    },
    BlockAccepted {
        block: SignedBlock,
    },
}

#[derive(Debug)]
struct RuntimeState {
    chain: ChainState,
    mempool: BTreeMap<String, SignedTransaction>,
    receipts: BTreeMap<String, Vec<SignedHealthReceipt>>,
    browser_receipts: BTreeMap<String, Vec<SignedBrowserReceipt>>,
    compute_receipts: BTreeMap<String, Vec<SignedComputeReceipt>>,
    storage_proof_receipts: BTreeMap<String, Vec<SignedStorageProofReceipt>>,
    heartbeat_observations: BTreeMap<String, Vec<SignedHeartbeatObservation>>,
    heartbeat_client_nonces: BTreeMap<String, DateTime<Utc>>,
    block_approvals: BTreeMap<String, SignedBlockApproval>,
    delivered_alerts: BTreeMap<String, DateTime<Utc>>,
    active_view: u64,
    view_started_at: DateTime<Utc>,
    seen_txs: BTreeSet<String>,
    seen_receipts: BTreeSet<String>,
    seen_browser_receipts: BTreeSet<String>,
    seen_compute_receipts: BTreeSet<String>,
    seen_storage_proof_receipts: BTreeSet<String>,
    seen_heartbeat_observations: BTreeSet<String>,
    seen_blocks: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct ApplyTransactionResult {
    accepted: bool,
    should_execute: bool,
}

#[derive(Clone)]
pub struct NodeRuntime {
    config: NodeConfig,
    wallet: Wallet,
    http_client: reqwest::Client,
    swap_registry: Arc<SwapRegistry>,
    persist_lock: Arc<Mutex<()>>,
    state: Arc<RwLock<RuntimeState>>,
}

#[derive(Debug, Serialize)]
struct SubmittedResponse {
    accepted: bool,
    id: String,
}

#[derive(Debug, Serialize)]
struct AccountResponse {
    address: Address,
    balance: u64,
    balance_display: String,
    storage_balance: u64,
    storage_balance_display: String,
    compute_balance: u64,
    compute_balance_display: String,
    dns_balance: u64,
    dns_balance_display: String,
    nonce: u64,
    locked_balance: u64,
}

#[derive(Debug, Serialize)]
struct JobResponse {
    tx_hash: String,
    finalized: bool,
    finalized_record: Option<FinalizedHealthCheck>,
    finalized_health_record: Option<FinalizedHealthCheck>,
    finalized_browser_record: Option<FinalizedBrowserCheck>,
    finalized_compute_record: Option<FinalizedComputeJob>,
    pending_health_receipts: usize,
    pending_browser_receipts: usize,
    pending_compute_receipts: usize,
}

#[derive(Debug, Serialize)]
struct MonitorResponse {
    monitor: MonitorRecord,
}

#[derive(Debug, Serialize)]
struct MonitorListResponse {
    monitors: Vec<MonitorRecord>,
}

#[derive(Debug, Serialize)]
struct MonitorSlotsResponse {
    monitor_id: String,
    slots: Vec<MonitorSlotRecord>,
}

#[derive(Debug, Serialize)]
struct MonitorAlertsResponse {
    monitor_id: String,
    alerts: Vec<AlertFact>,
}

#[derive(Debug, Serialize)]
struct PingAcceptedResponse {
    accepted: bool,
    monitor_id: String,
    slot_key: String,
    observation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MonitorConfirmRequest {
    monitor_id: String,
    slot_key: String,
    assigned_validator_count: usize,
    #[serde(default)]
    direct_probe: bool,
}

#[derive(Debug, Clone)]
struct ScheduledBrowserTask {
    monitor: MonitorRecord,
    slot_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MonitorConfirmationContribution {
    #[serde(default)]
    validator_receipt: Option<SignedHealthReceipt>,
    #[serde(default)]
    delegated_receipts: Vec<SignedDelegatedProbeReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProbeAgentRegistry {
    #[serde(default)]
    agents: Vec<ConfiguredProbeAgent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfiguredProbeAgent {
    public_key: String,
    endpoint: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    api_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PingSignalQuery {
    signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NotificationPolicyStore {
    #[serde(default)]
    policies: BTreeMap<String, NotificationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NotificationPolicy {
    #[serde(default)]
    webhooks: Vec<WebhookDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookDestination {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SwapLockResponse {
    quote_id: String,
    pending: bool,
    record: Option<PendingSwapLock>,
}

#[derive(Debug, Serialize)]
struct AdaptersResponse {
    adapters: Vec<String>,
}

#[derive(Debug, Serialize)]
struct StorageContractResponse {
    contract: StorageContractRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeStatusResponse {
    version: String,
    node_address: Address,
    chain_id: String,
    height: u64,
    last_block_hash: String,
    validator: bool,
    validator_count: usize,
    active_view: u64,
    min_health_receipts: usize,
    block_approval_quorum: usize,
    max_block_transactions: usize,
    block_time_secs: u64,
    mempool_size: usize,
    pending_receipt_count: usize,
    pending_swap_locks: usize,
    storage_contracts: usize,
    domain_offerings: usize,
    domain_leases: usize,
    pending_storage_proof_receipts: usize,
    finalized_health_checks: usize,
    finalized_browser_checks: usize,
    finalized_compute_jobs: usize,
    control_api_auth_enabled: bool,
    gossip_api_auth_enabled: bool,
    peers: Vec<String>,
}

impl NodeRuntime {
    pub async fn from_config(config: NodeConfig) -> Result<Self> {
        fs::create_dir_all(&config.state_dir).await?;
        fs::create_dir_all(block_archive_dir(&config.state_dir)).await?;
        fs::create_dir_all(health_check_archive_dir(&config.state_dir)).await?;
        fs::create_dir_all(browser_check_archive_dir(&config.state_dir)).await?;
        fs::create_dir_all(compute_job_archive_dir(&config.state_dir)).await?;
        fs::create_dir_all(browser_artifact_dir(&config.state_dir)).await?;
        fs::create_dir_all(compute_artifact_dir(&config.state_dir)).await?;
        fs::create_dir_all(compute_sandbox_dir(&config.state_dir)).await?;
        fs::create_dir_all(
            config
                .browser_cache_dir
                .clone()
                .unwrap_or_else(|| config.state_dir.join("browser_cache")),
        )
        .await?;

        let wallet = Wallet::from_file(&config.wallet_path, config.wallet_passphrase.as_deref())?;
        let genesis = load_genesis(&config.genesis_path).await?;
        let persisted = load_state(config.state_dir.join("state.json"), &genesis).await?;
        let journal_events = load_journal_events(&config.state_dir).await?;
        let migrated_finalized_blocks = persisted.finalized_blocks.clone();
        let migrated_finalized_health_checks = persisted.chain.finalized_health_checks.clone();
        let migrated_finalized_browser_checks = persisted.chain.finalized_browser_checks.clone();
        let migrated_finalized_compute_jobs = persisted.chain.finalized_compute_jobs.clone();
        migrate_legacy_archives(
            &config.state_dir,
            &migrated_finalized_blocks,
            &migrated_finalized_health_checks,
            &migrated_finalized_browser_checks,
            &migrated_finalized_compute_jobs,
        )
        .await?;
        let swap_registry = Arc::new(SwapRegistry::from_optional_file(
            config.swap_config_path.as_deref(),
        )?);
        let state = RuntimeState {
            seen_txs: persisted.mempool.keys().cloned().collect(),
            seen_receipts: persisted
                .receipts
                .values()
                .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
                .collect(),
            seen_browser_receipts: persisted
                .browser_receipts
                .values()
                .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
                .collect(),
            seen_compute_receipts: persisted
                .compute_receipts
                .values()
                .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
                .collect(),
            seen_storage_proof_receipts: persisted
                .storage_proof_receipts
                .values()
                .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
                .collect(),
            seen_heartbeat_observations: persisted
                .heartbeat_observations
                .values()
                .flat_map(|items| items.iter().map(|item| item.id.clone()))
                .collect(),
            seen_blocks: persisted
                .chain
                .block_history
                .iter()
                .cloned()
                .chain(std::iter::once(persisted.chain.last_block_hash.clone()))
                .collect(),
            chain: persisted.chain,
            mempool: persisted.mempool,
            receipts: persisted.receipts,
            browser_receipts: persisted.browser_receipts,
            compute_receipts: persisted.compute_receipts,
            storage_proof_receipts: persisted.storage_proof_receipts,
            heartbeat_observations: persisted.heartbeat_observations,
            heartbeat_client_nonces: persisted.heartbeat_client_nonces,
            block_approvals: persisted.block_approvals,
            delivered_alerts: persisted.delivered_alerts,
            active_view: persisted.active_view,
            view_started_at: persisted.view_started_at,
        };

        let runtime = Self {
            config,
            wallet,
            http_client: reqwest::Client::new(),
            swap_registry,
            persist_lock: Arc::new(Mutex::new(())),
            state: Arc::new(RwLock::new(state)),
        };
        runtime.replay_journal_events(journal_events).await?;
        {
            let mut state = runtime.state.write().await;
            prune_pending_state(&mut state);
        }
        runtime.snapshot_and_compact_journal().await?;
        runtime.schedule_pending_check_executions().await;
        Ok(runtime)
    }

    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    fn require_control_auth(&self, headers: &HeaderMap) -> Result<()> {
        require_bearer_token(
            headers,
            self.config.control_api_token.as_deref(),
            "control API",
        )
    }

    fn require_gossip_auth(&self, headers: &HeaderMap) -> Result<()> {
        require_bearer_token(
            headers,
            self.config.gossip_api_token.as_deref(),
            "gossip API",
        )
    }

    pub async fn run(self) -> Result<()> {
        let runtime = Arc::new(self);
        let block_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = block_runtime.block_producer_loop().await {
                error!(?error, "block producer loop exited");
            }
        });
        let sync_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = sync_runtime.sync_loop().await {
                error!(?error, "peer sync loop exited");
            }
        });

        let app = Router::new()
            .route("/v1/control/status", get(get_status))
            .route("/v1/control/account/:address", get(get_account))
            .route("/v1/control/ledger", get(get_ledger))
            .route("/v1/control/jobs/:tx_hash", get(get_job))
            .route(
                "/v1/control/monitors",
                get(list_monitors).post(create_monitor),
            )
            .route(
                "/v1/control/monitors/:monitor_id",
                get(get_monitor).put(update_monitor).delete(delete_monitor),
            )
            .route(
                "/v1/control/monitors/:monitor_id/pause",
                post(pause_monitor),
            )
            .route(
                "/v1/control/monitors/:monitor_id/resume",
                post(resume_monitor),
            )
            .route(
                "/v1/control/monitors/:monitor_id/topup",
                post(topup_monitor),
            )
            .route(
                "/v1/control/monitors/:monitor_id/rotate-token",
                post(rotate_monitor_token),
            )
            .route(
                "/v1/control/monitors/:monitor_id/slots",
                get(get_monitor_slots),
            )
            .route(
                "/v1/control/monitors/:monitor_id/alerts",
                get(get_monitor_alerts),
            )
            .route("/v1/control/swaps/:quote_id", get(get_swap_lock))
            .route(
                "/v1/control/storage/:contract_id",
                get(get_storage_contract),
            )
            .route(
                "/v1/control/compute-artifacts/:tx_hash/:shard_id/*path",
                get(get_compute_artifact),
            )
            .route("/v1/control/domain-route/:host", get(get_domain_route))
            .route("/v1/control/adapters", get(get_adapters))
            .route("/v1/control/submit", post(submit_transaction))
            .route("/v1/control/swap/quote", post(quote_swap))
            .route("/v1/ping/:monitor_id/:token", get(ping_success_get))
            .route("/v1/ping/:monitor_id/:token", post(ping_success_post))
            .route("/v1/ping/:monitor_id/:token/start", get(ping_start_get))
            .route("/v1/ping/:monitor_id/:token/start", post(ping_start_post))
            .route("/v1/ping/:monitor_id/:token/fail", get(ping_fail_get))
            .route("/v1/ping/:monitor_id/:token/fail", post(ping_fail_post))
            .route("/v1/ping/:monitor_id", post(ping_signed_post))
            .route("/v1/internal/tx", post(gossip_transaction))
            .route("/v1/internal/receipt", post(gossip_receipt))
            .route("/v1/internal/browser-receipt", post(gossip_browser_receipt))
            .route("/v1/internal/compute-receipt", post(gossip_compute_receipt))
            .route(
                "/v1/internal/storage-proof",
                post(gossip_storage_proof_receipt),
            )
            .route("/v1/internal/heartbeat", post(gossip_heartbeat_observation))
            .route(
                "/v1/internal/monitor/confirm",
                post(run_monitor_confirmation),
            )
            .route("/v1/internal/block/approve", post(approve_block))
            .route("/v1/internal/block/:height", get(get_internal_block))
            .route("/v1/internal/block", post(gossip_block))
            .with_state(runtime.clone());

        let listener = tokio::net::TcpListener::bind(runtime.config.bind_addr).await?;
        info!(
            address = %runtime.address(),
            bind = %runtime.config.bind_addr,
            peers = runtime.config.peers.len(),
            "gossip_protocol node listening"
        );
        axum::serve(listener, app).await?;
        Ok(())
    }

    async fn block_producer_loop(self: Arc<Self>) -> Result<()> {
        let block_time_secs = {
            let state = self.state.read().await;
            state.chain.block_time_secs
        };
        let mut ticker = interval(Duration::from_secs(block_time_secs.max(1)));
        loop {
            ticker.tick().await;
            self.advance_view_if_stale().await?;
            if let Err(error) = self.maybe_produce_block().await {
                warn!(?error, "block production attempt failed");
            }
        }
    }

    async fn sync_loop(self: Arc<Self>) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(PEER_SYNC_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            if let Err(error) = self.sync_with_peers().await {
                warn!(?error, "peer sync attempt failed");
            }
        }
    }

    async fn advance_view_if_stale(&self) -> Result<()> {
        let _persist_guard = self.persist_lock.lock().await;
        let view_event = {
            let mut state = self.state.write().await;
            if state.mempool.is_empty() && state.storage_proof_receipts.is_empty() {
                None
            } else {
                let elapsed = Utc::now() - state.view_started_at;
                let timeout = chrono::Duration::seconds(state.chain.block_time_secs.max(1) as i64);
                if elapsed < timeout {
                    None
                } else {
                    state.active_view += 1;
                    state.view_started_at = Utc::now();
                    retain_current_block_approval_slot(&mut state);
                    Some(PersistedJournalEvent::ViewAdvanced {
                        active_view: state.active_view,
                        view_started_at: state.view_started_at,
                    })
                }
            }
        };
        if let Some(view_event) = view_event {
            self.append_journal_event_locked(&view_event).await?;
        }
        Ok(())
    }

    async fn sync_with_peers(&self) -> Result<()> {
        if self.config.peers.is_empty() {
            return Ok(());
        }

        let local_status = self.status_response().await;
        let mut highest_peer_height = local_status.height;
        let peer_statuses = join_all(self.config.peers.iter().map(|peer| async move {
            let url = format!("{}/v1/control/status", peer.trim_end_matches('/'));
            match self.http_client.get(url).send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<NodeStatusResponse>().await {
                        Ok(status) => Some((peer.clone(), status)),
                        Err(error) => {
                            warn!(?error, peer, "peer returned unreadable status");
                            None
                        }
                    }
                }
                Ok(response) => {
                    warn!(status = ?response.status(), peer, "peer rejected status request");
                    None
                }
                Err(error) => {
                    warn!(?error, peer, "failed to fetch peer status");
                    None
                }
            }
        }))
        .await;

        let mut candidates = Vec::new();
        for (peer, status) in peer_statuses.into_iter().flatten() {
            if status.chain_id != local_status.chain_id {
                continue;
            }
            highest_peer_height = highest_peer_height.max(status.height);
            if status.height > local_status.height {
                candidates.push((peer, status));
            } else if status.height == local_status.height
                && status.last_block_hash != local_status.last_block_hash
            {
                warn!(
                    peer,
                    local_height = local_status.height,
                    local_hash = %local_status.last_block_hash,
                    peer_hash = %status.last_block_hash,
                    "peer is on a different chain head at the same height"
                );
            }
        }

        candidates.sort_by(|left, right| right.1.height.cmp(&left.1.height));
        for (peer, status) in candidates {
            let current_height = {
                let state = self.state.read().await;
                state.chain.height
            };
            if current_height >= highest_peer_height {
                break;
            }
            if let Err(error) = self.catch_up_from_peer(&peer, status.height).await {
                warn!(
                    ?error,
                    peer,
                    target_height = status.height,
                    "failed to catch up from peer"
                );
            }
        }

        Ok(())
    }

    async fn catch_up_from_peer(&self, peer: &str, target_height: u64) -> Result<()> {
        loop {
            let next_height = {
                let state = self.state.read().await;
                if state.chain.height >= target_height {
                    break;
                }
                state.chain.height + 1
            };

            let Some(block) = self.fetch_block_from_peer(peer, next_height).await? else {
                bail!("peer did not provide block {next_height}");
            };

            let accepted = self.accept_block(block.clone(), false).await?;
            if !accepted {
                let state = self.state.read().await;
                if state.chain.height >= next_height {
                    continue;
                }
                bail!("peer block {next_height} was not accepted locally");
            }
            info!(
                peer,
                height = block.body.height,
                hash = %block.hash,
                "caught up missing block from peer"
            );
        }
        Ok(())
    }

    async fn fetch_block_from_peer(&self, peer: &str, height: u64) -> Result<Option<SignedBlock>> {
        let url = format!(
            "{}/v1/internal/block/{}",
            peer.trim_end_matches('/'),
            height
        );
        let mut request = self.http_client.get(url);
        if let Some(token) = self.config.gossip_api_token.as_deref() {
            request = request.header(AUTHORIZATION, bearer_token_value(token));
        }
        let response = request.send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            bail!("peer returned {}", response.status());
        }
        Ok(Some(response.json::<SignedBlock>().await?))
    }

    async fn maybe_produce_block(&self) -> Result<()> {
        let (start_height, start_hash, start_view, has_pending_work) = {
            let state = self.state.read().await;
            let has_due_monitor_work = monitor_due_work_exists(
                &state.chain,
                &state.browser_receipts,
                &state.heartbeat_observations,
                Utc::now(),
            )
            .unwrap_or(false);
            (
                state.chain.height,
                state.chain.last_block_hash.clone(),
                state.active_view,
                !state.mempool.is_empty()
                    || !state.heartbeat_observations.is_empty()
                    || !state.storage_proof_receipts.is_empty()
                    || !state.compute_receipts.is_empty()
                    || has_due_monitor_work,
            )
        };
        if !has_pending_work {
            return Ok(());
        }
        let priority_index = {
            let state = self.state.read().await;
            state
                .chain
                .validators
                .iter()
                .position(|validator| validator == &self.address())
        };
        let Some(priority_index) = priority_index else {
            return Ok(());
        };
        sleep(Duration::from_millis(
            priority_index as u64 * PROPOSAL_STAGGER_MS,
        ))
        .await;

        let (
            chain,
            mempool,
            receipts,
            browser_receipts,
            compute_receipts,
            storage_proof_receipts,
            heartbeat_observations,
            active_view,
        ) = {
            let state = self.state.read().await;
            if state.chain.height != start_height
                || state.chain.last_block_hash != start_hash
                || state.active_view != start_view
            {
                return Ok(());
            }
            let has_due_monitor_work = monitor_due_work_exists(
                &state.chain,
                &state.browser_receipts,
                &state.heartbeat_observations,
                Utc::now(),
            )
            .unwrap_or(false);
            if !state.chain.validators.contains(&self.address())
                || (state.mempool.is_empty()
                    && state.heartbeat_observations.is_empty()
                    && state.storage_proof_receipts.is_empty()
                    && state.compute_receipts.is_empty()
                    && !has_due_monitor_work)
            {
                return Ok(());
            }
            (
                state.chain.clone(),
                state.mempool.clone(),
                state.receipts.clone(),
                state.browser_receipts.clone(),
                state.compute_receipts.clone(),
                state.storage_proof_receipts.clone(),
                state.heartbeat_observations.clone(),
                state.active_view,
            )
        };

        let next_height = chain.height + 1;
        if chain.scheduled_proposer_for_view(next_height, active_view) != &self.address() {
            return Ok(());
        }
        let mut candidate_txs: Vec<SignedTransaction> = mempool.into_values().collect();
        candidate_txs.sort_by(|left, right| {
            left.body
                .nonce
                .cmp(&right.body.nonce)
                .then_with(|| left.body.created_at.cmp(&right.body.created_at))
        });

        let mut simulated = chain.clone();
        let mut selected = Vec::new();
        let mut health_batches = Vec::new();
        let mut browser_batches = Vec::new();
        let mut compute_batches = Vec::new();
        let mut storage_proof_batches = Vec::new();
        let proposed_at = Utc::now();
        let (heartbeat_items, monitor_evaluations, monitor_browser_batches, confirmation_batches) =
            self.prepare_monitor_work(
                &chain,
                &browser_receipts,
                &heartbeat_observations,
                proposed_at,
            )
            .await?;

        for tx in candidate_txs {
            if selected.len() >= MAX_BLOCK_TRANSACTIONS {
                break;
            }
            if simulated.validate_transaction_basic(&tx).is_err() {
                continue;
            }
            if simulated.account(&tx.signer).nonce + 1 != tx.body.nonce {
                continue;
            }

            match &tx.body.kind {
                TransactionKind::Transfer { amount, .. } => {
                    if simulated.spendable_balance(&tx.signer) < *amount {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        next_selected.push(tx.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                    }
                }
                TransactionKind::StorageTransfer { amount, .. } => {
                    if simulated.account(&tx.signer).storage_balance < *amount {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        next_selected.push(tx.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                    }
                }
                TransactionKind::ComputeTransfer { amount, .. } => {
                    if simulated.account(&tx.signer).compute_balance < *amount {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        next_selected.push(tx.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                    }
                }
                TransactionKind::DnsTransfer { amount, .. } => {
                    if simulated.account(&tx.signer).dns_balance < *amount {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        next_selected.push(tx.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                    }
                }
                TransactionKind::SwapLock { .. }
                | TransactionKind::SwapCancel { .. }
                | TransactionKind::SwapSettle { .. }
                | TransactionKind::MonitorCreate { .. }
                | TransactionKind::MonitorUpdate { .. }
                | TransactionKind::MonitorPause { .. }
                | TransactionKind::MonitorResume { .. }
                | TransactionKind::MonitorTopUp { .. }
                | TransactionKind::MonitorDelete { .. }
                | TransactionKind::StorageCreate { .. }
                | TransactionKind::StorageTopUp { .. }
                | TransactionKind::StorageCancel { .. }
                | TransactionKind::DomainOfferingCreate { .. }
                | TransactionKind::DomainOfferingPause { .. }
                | TransactionKind::DomainOfferingResume { .. }
                | TransactionKind::DomainOfferingRetire { .. }
                | TransactionKind::DomainLeaseCreate { .. }
                | TransactionKind::DomainLeaseRenew { .. }
                | TransactionKind::DomainLeaseBind { .. }
                | TransactionKind::DomainLeaseCancel { .. } => {
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        next_selected.push(tx.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                    }
                }
                TransactionKind::HealthCheck { .. } => {
                    let Some(job_receipts) = receipts.get(&tx.hash) else {
                        continue;
                    };
                    let Ok(batch) = simulated.summarize_receipts_for_tx(&tx, job_receipts) else {
                        continue;
                    };
                    if batch.receipts.len() < simulated.min_health_receipts {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: vec![batch.clone()],
                        browser_batches: Vec::new(),
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        let mut next_batches = health_batches.clone();
                        next_selected.push(tx.clone());
                        next_batches.push(batch.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &next_batches,
                            &browser_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                        health_batches = next_batches;
                    }
                }
                TransactionKind::BrowserCheck { .. } => {
                    let Some(job_receipts) = browser_receipts.get(&tx.hash) else {
                        continue;
                    };
                    let Ok(batch) = simulated.summarize_browser_receipts_for_tx(&tx, job_receipts)
                    else {
                        continue;
                    };
                    if batch.receipts.len() < simulated.min_health_receipts {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: vec![batch.clone()],
                        compute_batches: Vec::new(),
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        let mut next_batches = browser_batches.clone();
                        next_selected.push(tx.clone());
                        next_batches.push(batch.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &next_batches,
                            &compute_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                        browser_batches = next_batches;
                    }
                }
                TransactionKind::ComputeJob { spec } => {
                    let Some(job_receipts) = compute_receipts.get(&tx.hash) else {
                        continue;
                    };
                    let Ok(batch) = simulated.summarize_compute_receipts_for_tx(&tx, job_receipts)
                    else {
                        continue;
                    };
                    let required = usize::from(spec.replication)
                        .max(simulated.min_health_receipts)
                        .min(simulated.validators.len());
                    if batch.receipts.len() < required {
                        continue;
                    }
                    let block = BlockBody {
                        chain_id: simulated.chain_id.clone(),
                        height: simulated.height + 1,
                        view: active_view,
                        previous_hash: simulated.last_block_hash.clone(),
                        proposer: self.address(),
                        proposed_at: Utc::now(),
                        transactions: vec![tx.clone()],
                        health_batches: Vec::new(),
                        browser_batches: Vec::new(),
                        compute_batches: vec![batch.clone()],
                        monitor_browser_batches: Vec::new(),
                        heartbeat_observations: Vec::new(),
                        monitor_evaluations: Vec::new(),
                        confirmation_batches: Vec::new(),
                        storage_proof_batches: Vec::new(),
                    };
                    if let Ok(next_state) = simulated.simulate_apply(&block) {
                        let mut next_selected = selected.clone();
                        let mut next_batches = compute_batches.clone();
                        next_selected.push(tx.clone());
                        next_batches.push(batch.clone());
                        if !candidate_block_fits_limits(
                            &chain.chain_id,
                            next_height,
                            active_view,
                            &chain.last_block_hash,
                            &self.address(),
                            &next_selected,
                            &health_batches,
                            &browser_batches,
                            &next_batches,
                            &monitor_browser_batches,
                            &heartbeat_items,
                            &monitor_evaluations,
                            &confirmation_batches,
                            &storage_proof_batches,
                        )? {
                            break;
                        }
                        simulated = next_state;
                        selected = next_selected;
                        compute_batches = next_batches;
                    }
                }
            }
        }

        let mut seen_storage_contracts = BTreeSet::new();
        for receipts in storage_proof_receipts.values() {
            let Some(first) = receipts.first() else {
                continue;
            };
            if !seen_storage_contracts.insert(first.body.contract_id.clone()) {
                continue;
            }
            let Ok(batch) = simulated.summarize_storage_proof_batch(
                &first.body.contract_id,
                receipts,
                &chain.last_block_hash,
                proposed_at,
            ) else {
                continue;
            };
            let proof_block = BlockBody {
                chain_id: simulated.chain_id.clone(),
                height: simulated.height + 1,
                view: active_view,
                previous_hash: simulated.last_block_hash.clone(),
                proposer: self.address(),
                proposed_at,
                transactions: Vec::new(),
                health_batches: Vec::new(),
                browser_batches: Vec::new(),
                compute_batches: Vec::new(),
                monitor_browser_batches: Vec::new(),
                heartbeat_observations: Vec::new(),
                monitor_evaluations: Vec::new(),
                confirmation_batches: Vec::new(),
                storage_proof_batches: vec![batch.clone()],
            };
            let Ok(next_state) = simulated.simulate_apply(&proof_block) else {
                continue;
            };
            let mut next_storage_batches = storage_proof_batches.clone();
            next_storage_batches.push(batch.clone());
            if !candidate_block_fits_limits(
                &chain.chain_id,
                next_height,
                active_view,
                &chain.last_block_hash,
                &self.address(),
                &selected,
                &health_batches,
                &browser_batches,
                &compute_batches,
                &monitor_browser_batches,
                &heartbeat_items,
                &monitor_evaluations,
                &confirmation_batches,
                &next_storage_batches,
            )? {
                break;
            }
            simulated = next_state;
            storage_proof_batches = next_storage_batches;
        }

        if selected.is_empty()
            && health_batches.is_empty()
            && browser_batches.is_empty()
            && compute_batches.is_empty()
            && monitor_browser_batches.is_empty()
            && heartbeat_items.is_empty()
            && monitor_evaluations.is_empty()
            && confirmation_batches.is_empty()
            && storage_proof_batches.is_empty()
        {
            return Ok(());
        }

        let mut block = self.wallet.sign_block(SignedBlock {
            hash: String::new(),
            body: BlockBody {
                chain_id: chain.chain_id.clone(),
                height: next_height,
                view: active_view,
                previous_hash: chain.last_block_hash.clone(),
                proposer: String::new(),
                proposed_at,
                transactions: selected,
                health_batches,
                browser_batches,
                compute_batches,
                monitor_browser_batches,
                heartbeat_observations: heartbeat_items,
                monitor_evaluations,
                confirmation_batches,
                storage_proof_batches,
            },
            signature: String::new(),
            approvals: Vec::new(),
        })?;
        let mut approval_map = BTreeMap::new();
        let local_approval = self.approve_block_proposal(&block).await?;
        approval_map.insert(local_approval.body.approver.clone(), local_approval);
        for approval in self.request_block_approvals(&block).await {
            approval_map
                .entry(approval.body.approver.clone())
                .or_insert(approval);
        }
        block.approvals = approval_map.into_values().collect();
        if block.approvals.len() < chain.required_block_approvals() {
            warn!(
                height = block.body.height,
                view = block.body.view,
                approvals = block.approvals.len(),
                required = chain.required_block_approvals(),
                "insufficient validator approvals for block proposal"
            );
            return Ok(());
        }

        let accepted = self.accept_block(block.clone(), true).await?;
        if accepted {
            info!(
                height = block.body.height,
                view = block.body.view,
                hash = %block.hash,
                approvals = block.approvals.len(),
                "produced block"
            );
        }
        Ok(())
    }

    pub async fn accept_transaction(&self, tx: SignedTransaction, broadcast: bool) -> Result<bool> {
        let should_execute = {
            let _persist_guard = self.persist_lock.lock().await;
            let outcome = {
                let mut state = self.state.write().await;
                apply_transaction_to_state(&mut state, &self.address(), tx.clone())?
            };
            if !outcome.accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(&PersistedJournalEvent::TransactionAccepted {
                tx: tx.clone(),
            })
            .await?;
            outcome.should_execute
        };

        if broadcast {
            self.broadcast("/v1/internal/tx", &tx).await;
        }
        if should_execute {
            match tx.body.kind {
                TransactionKind::HealthCheck { .. } => self.spawn_health_execution(tx).await,
                TransactionKind::BrowserCheck { .. } => self.spawn_browser_execution(tx).await,
                TransactionKind::ComputeJob { .. } => self.spawn_compute_execution(tx).await,
                _ => {}
            }
        }
        Ok(true)
    }

    pub async fn accept_receipt(
        &self,
        receipt: SignedHealthReceipt,
        broadcast: bool,
    ) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let accepted = {
                let mut state = self.state.write().await;
                apply_receipt_to_state(&mut state, receipt.clone())?
            };
            if !accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(&PersistedJournalEvent::ReceiptAccepted {
                receipt: receipt.clone(),
            })
            .await?;
        }
        if broadcast {
            self.broadcast("/v1/internal/receipt", &receipt).await;
        }
        Ok(true)
    }

    pub async fn accept_compute_receipt(
        &self,
        receipt: SignedComputeReceipt,
        broadcast: bool,
    ) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let accepted = {
                let mut state = self.state.write().await;
                apply_compute_receipt_to_state(&mut state, receipt.clone())?
            };
            if !accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(&PersistedJournalEvent::ComputeReceiptAccepted {
                receipt: receipt.clone(),
            })
            .await?;
        }
        if broadcast {
            self.broadcast("/v1/internal/compute-receipt", &receipt)
                .await;
        }
        Ok(true)
    }

    pub async fn accept_browser_receipt(
        &self,
        receipt: SignedBrowserReceipt,
        broadcast: bool,
    ) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let accepted = {
                let mut state = self.state.write().await;
                apply_browser_receipt_to_state(&mut state, receipt.clone())?
            };
            if !accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(&PersistedJournalEvent::BrowserReceiptAccepted {
                receipt: receipt.clone(),
            })
            .await?;
        }
        if broadcast {
            self.broadcast("/v1/internal/browser-receipt", &receipt)
                .await;
        }
        Ok(true)
    }

    pub async fn accept_storage_proof_receipt(
        &self,
        receipt: SignedStorageProofReceipt,
        broadcast: bool,
    ) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let accepted = {
                let mut state = self.state.write().await;
                apply_storage_proof_receipt_to_state(&mut state, receipt.clone())?
            };
            if !accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(&PersistedJournalEvent::StorageProofReceiptAccepted {
                receipt: receipt.clone(),
            })
            .await?;
        }
        if broadcast {
            self.broadcast("/v1/internal/storage-proof", &receipt).await;
        }
        Ok(true)
    }

    pub async fn accept_heartbeat_observation(
        &self,
        observation: SignedHeartbeatObservation,
        broadcast: bool,
    ) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let accepted = {
                let mut state = self.state.write().await;
                apply_heartbeat_observation_to_state(&mut state, observation.clone())?
            };
            if !accepted {
                return Ok(false);
            }
            self.append_journal_event_locked(
                &PersistedJournalEvent::HeartbeatObservationAccepted {
                    observation: observation.clone(),
                },
            )
            .await?;
        }
        if broadcast {
            self.broadcast("/v1/internal/heartbeat", &observation).await;
        }
        Ok(true)
    }

    pub async fn accept_block(&self, block: SignedBlock, broadcast: bool) -> Result<bool> {
        {
            let _persist_guard = self.persist_lock.lock().await;
            let Some((
                finalized_health_records,
                finalized_browser_records,
                finalized_compute_records,
            )) = ({
                let mut state = self.state.write().await;
                apply_block_to_state(&mut state, block.clone())?
            })
            else {
                return Ok(false);
            };
            self.append_journal_event_locked(&PersistedJournalEvent::BlockAccepted {
                block: block.clone(),
            })
            .await?;
            archive_block(&self.config.state_dir, &block).await?;
            for record in &finalized_health_records {
                archive_finalized_health_check(&self.config.state_dir, record).await?;
            }
            for record in &finalized_browser_records {
                archive_finalized_browser_check(&self.config.state_dir, record).await?;
            }
            for record in &finalized_compute_records {
                archive_finalized_compute_job(&self.config.state_dir, record).await?;
            }
            self.snapshot_and_compact_journal_locked().await?;
        }
        self.spawn_alert_delivery(block.clone()).await;
        self.schedule_pending_check_executions().await;
        if broadcast {
            self.broadcast("/v1/internal/block", &block).await;
        }
        Ok(true)
    }

    async fn approve_block_proposal(&self, block: &SignedBlock) -> Result<SignedBlockApproval> {
        let approval = {
            let _persist_guard = self.persist_lock.lock().await;
            let (approval, should_persist) = {
                let mut state = self.state.write().await;
                if !state.chain.validators.contains(&self.address()) {
                    bail!("node is not part of the validator set");
                }
                state.chain.validate_block_proposal(block)?;
                let slot_key = block_approval_slot_key(
                    block.body.height,
                    block.body.view,
                    &block.body.previous_hash,
                );
                if let Some(existing) = state.block_approvals.get(&slot_key) {
                    if existing.body.block_hash != block.hash {
                        bail!(
                            "validator already approved a different block for this height and view"
                        );
                    }
                    (existing.clone(), false)
                } else {
                    let approval = self.wallet.sign_block_approval(SignedBlockApproval {
                        id: String::new(),
                        body: BlockApprovalBody {
                            chain_id: state.chain.chain_id.clone(),
                            height: block.body.height,
                            view: block.body.view,
                            previous_hash: block.body.previous_hash.clone(),
                            block_hash: block.hash.clone(),
                            approver: String::new(),
                            approved_at: Utc::now(),
                        },
                        signature: String::new(),
                    })?;
                    state.block_approvals.insert(slot_key, approval.clone());
                    (approval, true)
                }
            };
            if should_persist {
                self.append_journal_event_locked(&PersistedJournalEvent::ApprovalStored {
                    approval: approval.clone(),
                })
                .await?;
            }
            approval
        };

        Ok(approval)
    }

    async fn request_block_approvals(&self, block: &SignedBlock) -> Vec<SignedBlockApproval> {
        let futures = self.config.peers.iter().map(|peer| async move {
            let url = format!("{}/v1/internal/block/approve", peer.trim_end_matches('/'));
            let mut request = self.http_client.post(url);
            if let Some(token) = self.config.gossip_api_token.as_deref() {
                request = request.header(AUTHORIZATION, bearer_token_value(token));
            }
            match request.json(block).send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<SignedBlockApproval>().await {
                        Ok(approval) => Some(approval),
                        Err(error) => {
                            warn!(?error, peer, "peer returned an unreadable block approval");
                            None
                        }
                    }
                }
                Ok(response) => {
                    warn!(status = ?response.status(), peer, "peer rejected block approval request");
                    None
                }
                Err(error) => {
                    warn!(?error, peer, "failed to request block approval");
                    None
                }
            }
        });
        join_all(futures).await.into_iter().flatten().collect()
    }

    async fn resolve_peer_directory(&self) -> BTreeMap<Address, String> {
        let futures = self.config.peers.iter().map(|peer| async move {
            let url = format!("{}/v1/control/status", peer.trim_end_matches('/'));
            match self.http_client.get(url).send().await {
                Ok(response) if response.status().is_success() => response
                    .json::<NodeStatusResponse>()
                    .await
                    .ok()
                    .map(|status| (status.node_address, peer.clone())),
                _ => None,
            }
        });
        join_all(futures).await.into_iter().flatten().collect()
    }

    async fn schedule_pending_check_executions(&self) {
        let (pending, scheduled_browser_tasks) = {
            let state = self.state.read().await;
            let pending = state
                .mempool
                .values()
                .filter(|tx| {
                    matches!(
                        tx.body.kind,
                        TransactionKind::HealthCheck { .. }
                            | TransactionKind::BrowserCheck { .. }
                            | TransactionKind::ComputeJob { .. }
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            let scheduled_browser_tasks =
                pending_monitor_browser_tasks(&state.chain, Utc::now()).unwrap_or_default();
            (pending, scheduled_browser_tasks)
        };
        for tx in pending {
            match tx.body.kind {
                TransactionKind::HealthCheck { .. } => self.spawn_health_execution(tx).await,
                TransactionKind::BrowserCheck { .. } => self.spawn_browser_execution(tx).await,
                TransactionKind::ComputeJob { .. } => self.spawn_compute_execution(tx).await,
                _ => {}
            }
        }
        for task in scheduled_browser_tasks {
            self.spawn_monitor_browser_execution(task).await;
        }
    }

    fn pending_check_plan(
        &self,
        chain: &ChainState,
        mempool: &BTreeMap<String, SignedTransaction>,
    ) -> Result<Option<(RoundRobinPlan, BTreeMap<String, usize>)>> {
        let mut health_checks = mempool
            .values()
            .filter(|tx| {
                matches!(
                    tx.body.kind,
                    TransactionKind::HealthCheck { .. } | TransactionKind::BrowserCheck { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        if health_checks.is_empty() {
            return Ok(None);
        }
        health_checks.sort_by(|left, right| {
            left.body
                .created_at
                .cmp(&right.body.created_at)
                .then_with(|| left.signer.cmp(&right.signer))
                .then_with(|| left.body.nonce.cmp(&right.body.nonce))
                .then_with(|| left.hash.cmp(&right.hash))
        });
        let task_keys = health_checks
            .iter()
            .map(|tx| tx.hash.clone())
            .collect::<Vec<_>>();
        let index_by_tx_hash = health_checks
            .iter()
            .enumerate()
            .map(|(index, tx)| (tx.hash.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let epoch_nonce = format!("health:{}:{}", chain.height + 1, chain.last_block_hash);
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::HealthCheck,
            &chain.chain_id,
            &epoch_nonce,
            &chain.validators,
            &task_keys,
            chain.min_health_receipts,
            chain.validators.len() > chain.min_health_receipts,
        )?;
        Ok(Some((plan, index_by_tx_hash)))
    }

    fn pending_monitor_browser_plan(
        &self,
        chain: &ChainState,
        tasks: &[ScheduledBrowserTask],
    ) -> Result<Option<(RoundRobinPlan, BTreeMap<String, usize>)>> {
        if tasks.is_empty() {
            return Ok(None);
        }
        let task_keys = tasks
            .iter()
            .map(|task| format!("{}:{}", task.monitor.monitor_id, task.slot_key))
            .collect::<Vec<_>>();
        let index_by_task = task_keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let epoch_nonce = format!(
            "monitor-browser:{}:{}:{}",
            chain.height + 1,
            chain.last_block_hash,
            task_keys.len()
        );
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::MonitorBrowser,
            &chain.chain_id,
            &epoch_nonce,
            &chain.validators,
            &task_keys,
            chain.min_health_receipts,
            chain.validators.len() > chain.min_health_receipts,
        )?;
        Ok(Some((plan, index_by_task)))
    }

    async fn prepare_monitor_work(
        &self,
        chain: &ChainState,
        pending_browser_receipts: &BTreeMap<String, Vec<SignedBrowserReceipt>>,
        pending_observations: &BTreeMap<String, Vec<SignedHeartbeatObservation>>,
        proposed_at: DateTime<Utc>,
    ) -> Result<(
        Vec<SignedHeartbeatObservation>,
        Vec<MonitorEvaluation>,
        Vec<MonitorBrowserBatch>,
        Vec<MonitorConfirmationBatch>,
    )> {
        let heartbeat_items = pending_observations
            .values()
            .flat_map(|items| items.iter().cloned())
            .collect::<Vec<_>>();
        let mut evaluation_seen = BTreeSet::new();
        let mut evaluations = Vec::new();
        let mut monitor_browser_batches = Vec::new();
        let mut confirmation_targets = Vec::new();

        for observation in &heartbeat_items {
            if observation.body.signal != HeartbeatSignal::Success {
                continue;
            }
            let existing_status = chain
                .monitor_slot_history
                .get(&observation.body.monitor_id)
                .and_then(|slots| slots.get(&observation.body.slot_key))
                .map(|slot| slot.status.clone());
            let kind = if matches!(
                existing_status,
                Some(
                    MonitorSlotStatus::MissedUnconfirmed
                        | MonitorSlotStatus::MissedServiceReachable
                        | MonitorSlotStatus::DownConfirmed
                        | MonitorSlotStatus::FailedExplicit
                )
            ) {
                MonitorEvaluationKind::Recovered
            } else {
                MonitorEvaluationKind::SlotSatisfied
            };
            if evaluation_seen.insert((
                observation.body.monitor_id.clone(),
                observation.body.slot_key.clone(),
                kind.clone(),
            )) {
                evaluations.push(MonitorEvaluation {
                    monitor_id: observation.body.monitor_id.clone(),
                    slot_key: observation.body.slot_key.clone(),
                    kind,
                    observed_at: proposed_at,
                });
            }
        }

        for monitor in chain.monitors.values() {
            let due_slots = due_monitor_slot_starts(chain, monitor, proposed_at)?;
            let minimum_balance = monitor_minimum_slot_balance(&monitor.spec)?;
            if !monitor.paused && monitor.budget_balance < minimum_balance {
                let slot_key = due_slots
                    .first()
                    .map(DateTime::<Utc>::to_rfc3339)
                    .or_else(|| monitor.next_slot_hint.clone())
                    .unwrap_or_else(|| proposed_at.to_rfc3339());
                if evaluation_seen.insert((
                    monitor.monitor_id.clone(),
                    slot_key.clone(),
                    MonitorEvaluationKind::InsufficientFunds,
                )) {
                    evaluations.push(MonitorEvaluation {
                        monitor_id: monitor.monitor_id.clone(),
                        slot_key,
                        kind: MonitorEvaluationKind::InsufficientFunds,
                        observed_at: proposed_at,
                    });
                }
            }

            for slot_started_at in due_slots {
                let slot_key = slot_started_at.to_rfc3339();
                let existing_status = chain
                    .monitor_slot_history
                    .get(&monitor.monitor_id)
                    .and_then(|slots| slots.get(&slot_key))
                    .map(|slot| slot.status.clone());

                let terminal = matches!(
                    existing_status,
                    Some(
                        MonitorSlotStatus::Ok
                            | MonitorSlotStatus::RecoveredLate
                            | MonitorSlotStatus::MissedUnconfirmed
                            | MonitorSlotStatus::MissedServiceReachable
                            | MonitorSlotStatus::DownConfirmed
                            | MonitorSlotStatus::InsufficientFunds
                    )
                );
                if let Some(heartbeat) = monitor.spec.heartbeat_config() {
                    let pending_key = heartbeat_slot_key(&monitor.monitor_id, &slot_key);
                    let slot_pending = pending_observations.get(&pending_key);
                    let has_success_pending = slot_pending
                        .map(|items| {
                            items
                                .iter()
                                .any(|item| item.body.signal == HeartbeatSignal::Success)
                        })
                        .unwrap_or(false);
                    let deadline_at = monitor_effective_deadline(
                        chain,
                        monitor,
                        slot_started_at,
                        slot_pending.map(Vec::as_slice),
                    )?;
                    if monitor.paused
                        || terminal
                        || has_success_pending
                        || proposed_at <= deadline_at
                    {
                        continue;
                    }
                    if evaluation_seen.insert((
                        monitor.monitor_id.clone(),
                        slot_key.clone(),
                        MonitorEvaluationKind::SlotMissed,
                    )) {
                        evaluations.push(MonitorEvaluation {
                            monitor_id: monitor.monitor_id.clone(),
                            slot_key: slot_key.clone(),
                            kind: MonitorEvaluationKind::SlotMissed,
                            observed_at: proposed_at,
                        });
                    }
                    if matches!(
                        heartbeat.miss_policy,
                        MissPolicy::ConfirmWithValidators { .. }
                            | MissPolicy::ConfirmWithDelegatedAgents { .. }
                    ) && heartbeat.confirmation_probe.is_some()
                    {
                        confirmation_targets.push((monitor.clone(), slot_key));
                    }
                    continue;
                }

                let deadline_at = slot_deadline(slot_started_at, monitor.spec.grace_secs);
                let synthetic_tx_hash = monitor_browser_tx_hash(&monitor.monitor_id, &slot_key)?;
                if let Some(receipts) = pending_browser_receipts.get(&synthetic_tx_hash)
                    && let Ok(batch) =
                        chain.summarize_monitor_browser_batch(monitor, &slot_key, receipts)
                {
                    monitor_browser_batches.push(batch);
                    continue;
                }
                if monitor.paused || terminal || proposed_at <= deadline_at {
                    continue;
                }
                if evaluation_seen.insert((
                    monitor.monitor_id.clone(),
                    slot_key.clone(),
                    MonitorEvaluationKind::SlotMissed,
                )) {
                    evaluations.push(MonitorEvaluation {
                        monitor_id: monitor.monitor_id.clone(),
                        slot_key,
                        kind: MonitorEvaluationKind::SlotMissed,
                        observed_at: proposed_at,
                    });
                }
            }
        }

        let confirmation_batches = self
            .plan_confirmation_batches(&chain.chain_id, chain, confirmation_targets)
            .await?;

        Ok((
            heartbeat_items,
            evaluations,
            monitor_browser_batches,
            confirmation_batches,
        ))
    }

    async fn plan_confirmation_batches(
        &self,
        chain_id: &str,
        chain: &ChainState,
        targets: Vec<(MonitorRecord, String)>,
    ) -> Result<Vec<MonitorConfirmationBatch>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let epoch_nonce = format!(
            "confirm:{}:{}:{}",
            chain.height + 1,
            chain.last_block_hash,
            targets.len()
        );
        let peer_directory = self.resolve_peer_directory().await;
        let mut grouped_targets = BTreeMap::<usize, Vec<(MonitorRecord, String)>>::new();
        for (monitor, slot_key) in targets {
            let heartbeat = monitor.spec.heartbeat_config().ok_or_else(|| {
                anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id)
            })?;
            let required = required_monitor_confirmation_receipts(
                heartbeat.miss_policy,
                chain.validators.len(),
            );
            if required == 0 {
                continue;
            }
            grouped_targets
                .entry(required)
                .or_default()
                .push((monitor, slot_key));
        }

        let mut confirmation_batches = Vec::new();
        for (required_replicas, targets) in grouped_targets {
            let task_keys = targets
                .iter()
                .map(|(monitor, slot_key)| format!("{}:{slot_key}", monitor.monitor_id))
                .collect::<Vec<_>>();
            let plan = RoundRobinPlan::build(
                RoundRobinDomain::MonitorConfirmation,
                chain_id,
                &epoch_nonce,
                &chain.validators,
                &task_keys,
                required_replicas,
                false,
            )?;
            for (task_index, (monitor, slot_key)) in targets.into_iter().enumerate() {
                let heartbeat = monitor.spec.heartbeat_config().ok_or_else(|| {
                    anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id)
                })?;
                let assignment = plan
                    .assignment_for_task(task_index)
                    .ok_or_else(|| anyhow!("missing confirmation assignment for {task_index}"))?;
                let batch = self
                    .request_monitor_confirmation_batch(
                        chain_id,
                        &monitor,
                        &slot_key,
                        &assignment.mandatory_providers,
                        &peer_directory,
                    )
                    .await?;
                let delegated_ok = match heartbeat.miss_policy {
                    MissPolicy::ConfirmWithDelegatedAgents {
                        require_region_diversity,
                        ..
                    } => {
                        let required_delegated = required_delegated_probe_receipts(
                            heartbeat.miss_policy,
                            assignment.mandatory_providers.len(),
                        );
                        let delegated_agents = batch
                            .delegated_receipts
                            .iter()
                            .map(|receipt| receipt.body.agent_public_key.clone())
                            .collect::<BTreeSet<_>>();
                        let delegated_regions = batch
                            .delegated_receipts
                            .iter()
                            .filter_map(|receipt| receipt.body.region.as_deref())
                            .map(str::trim)
                            .filter(|region| !region.is_empty())
                            .map(str::to_string)
                            .collect::<BTreeSet<_>>();
                        delegated_agents.len() >= required_delegated
                            && delegated_regions.len() >= *require_region_diversity
                    }
                    MissPolicy::RecordOnly | MissPolicy::ConfirmWithValidators { .. } => true,
                };
                if batch.validator_receipts.len() >= required_replicas && delegated_ok {
                    confirmation_batches.push(batch);
                }
            }
        }
        Ok(confirmation_batches)
    }

    async fn request_monitor_confirmation_batch(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
        assigned_validators: &[Address],
        peer_directory: &BTreeMap<Address, String>,
    ) -> Result<MonitorConfirmationBatch> {
        let mut validator_receipts = Vec::new();
        let mut delegated_receipts = Vec::new();
        let assigned_validator_count = assigned_validators.len();
        if assigned_validators
            .iter()
            .any(|validator| validator == &self.address())
        {
            let direct_probe = direct_validator_for_addresses(assigned_validators).as_deref()
                == Some(self.address().as_str());
            let contribution = self
                .execute_monitor_confirmation_contribution(
                    chain_id,
                    monitor,
                    slot_key,
                    assigned_validator_count,
                    direct_probe,
                )
                .await?;
            if let Some(receipt) = contribution.validator_receipt {
                validator_receipts.push(receipt);
                delegated_receipts.extend(contribution.delegated_receipts);
            }
        }
        let remote_validators = assigned_validators
            .iter()
            .filter(|validator| *validator != &self.address())
            .cloned()
            .collect::<Vec<_>>();
        let futures = remote_validators.iter().filter_map(|validator| {
            let peer = peer_directory.get(validator)?.clone();
            Some(async move {
                let url = format!("{}/v1/internal/monitor/confirm", peer.trim_end_matches('/'));
                let mut request = self.http_client.post(url);
                if let Some(token) = self.config.gossip_api_token.as_deref() {
                    request = request.header(AUTHORIZATION, bearer_token_value(token));
                }
                let payload = MonitorConfirmRequest {
                    monitor_id: monitor.monitor_id.clone(),
                    slot_key: slot_key.to_string(),
                    assigned_validator_count,
                    direct_probe: direct_validator_for_addresses(assigned_validators).as_deref()
                        == Some(validator.as_str()),
                };
                match request.json(&payload).send().await {
                    Ok(response) if response.status().is_success() => response
                        .json::<MonitorConfirmationContribution>()
                        .await
                        .ok()
                        .and_then(|contribution| {
                            let receipt = contribution.validator_receipt.as_ref()?;
                            if receipt.body.executor != *validator {
                                return None;
                            }
                            if contribution
                                .delegated_receipts
                                .iter()
                                .any(|item| item.body.parent_validator != *validator)
                            {
                                return None;
                            }
                            Some(contribution)
                        }),
                    _ => None,
                }
            })
        });
        for contribution in join_all(futures).await.into_iter().flatten() {
            if let Some(receipt) = contribution.validator_receipt {
                validator_receipts.push(receipt);
                delegated_receipts.extend(contribution.delegated_receipts);
            }
        }
        Ok(MonitorConfirmationBatch {
            monitor_id: monitor.monitor_id.clone(),
            slot_key: slot_key.to_string(),
            validator_receipts,
            delegated_receipts,
        })
    }

    async fn execute_monitor_confirmation_contribution(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
        assigned_validator_count: usize,
        direct_probe: bool,
    ) -> Result<MonitorConfirmationContribution> {
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let agents = self.configured_probe_agents().await?;
        let selected = self.select_local_probe_agents(
            chain_id,
            monitor,
            slot_key,
            assigned_validator_count,
            direct_probe,
            &agents,
        )?;
        let delegated_receipts = if selected.is_empty() {
            Vec::new()
        } else {
            self.dispatch_probe_agent_leases(chain_id, monitor, slot_key, &selected)
                .await?
        };
        let validator_receipt = if direct_probe {
            Some(
                self.execute_monitor_confirmation_direct(chain_id, monitor, slot_key)
                    .await?,
            )
        } else {
            self.summarize_delegated_receipts_as_validator_receipt(
                chain_id,
                monitor,
                slot_key,
                assigned_validator_count,
                &delegated_receipts,
            )?
        };
        if !direct_probe && validator_receipt.is_none() {
            bail!(
                "probe agents did not produce a verifiable confirmation result for {}:{}",
                monitor.monitor_id,
                slot_key
            );
        }
        let delegated_receipts = match heartbeat.miss_policy {
            MissPolicy::ConfirmWithDelegatedAgents { .. } => delegated_receipts,
            MissPolicy::RecordOnly | MissPolicy::ConfirmWithValidators { .. } => Vec::new(),
        };
        Ok(MonitorConfirmationContribution {
            validator_receipt,
            delegated_receipts,
        })
    }

    async fn configured_probe_agents(&self) -> Result<Vec<ConfiguredProbeAgent>> {
        let Some(path) = self.config.probe_agents_path.as_deref() else {
            return Ok(Vec::new());
        };
        let registry = read_json_optional::<ProbeAgentRegistry>(path)
            .await?
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        let mut agents = Vec::new();
        for agent in registry.agents {
            if !agent.enabled {
                continue;
            }
            if agent.public_key.trim().is_empty() {
                bail!("probe agent public_key cannot be empty");
            }
            if agent.endpoint.trim().is_empty() {
                bail!("probe agent endpoint cannot be empty");
            }
            if seen.insert(agent.public_key.clone()) {
                agents.push(agent);
            }
        }
        agents.sort_by(|left, right| {
            left.public_key
                .cmp(&right.public_key)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        Ok(agents)
    }

    fn select_local_probe_agents(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
        assigned_validator_count: usize,
        direct_probe: bool,
        agents: &[ConfiguredProbeAgent],
    ) -> Result<Vec<ConfiguredProbeAgent>> {
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let required = required_confirmation_execution_agents(
            heartbeat.miss_policy,
            assigned_validator_count,
            agents.len(),
            direct_probe,
        );
        let epoch_nonce = format!(
            "agent-confirm:{}:{}:{}",
            monitor.monitor_id, slot_key, assigned_validator_count
        );
        let task_key = format!("{}:{slot_key}:{}", monitor.monitor_id, self.address());
        self.select_round_robin_agents(chain_id, &epoch_nonce, &task_key, required, agents)
    }

    fn select_round_robin_agents(
        &self,
        chain_id: &str,
        epoch_nonce: &str,
        task_key: &str,
        required: usize,
        agents: &[ConfiguredProbeAgent],
    ) -> Result<Vec<ConfiguredProbeAgent>> {
        if required == 0 || agents.is_empty() {
            return Ok(Vec::new());
        }
        let providers = agents
            .iter()
            .map(|agent| agent.public_key.clone())
            .collect::<Vec<_>>();
        let task_keys = vec![task_key.to_string()];
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::MonitorConfirmation,
            chain_id,
            epoch_nonce,
            &providers,
            &task_keys,
            required,
            false,
        )?;
        let agent_directory = agents
            .iter()
            .map(|agent| (agent.public_key.clone(), agent.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut selected = Vec::new();
        let mut selected_keys = BTreeSet::new();
        let mut seen_regions = BTreeSet::new();

        for public_key in &plan.providers {
            if selected.len() >= required {
                break;
            }
            let Some(agent) = agent_directory.get(public_key) else {
                continue;
            };
            let Some(region) = agent.region.as_deref().map(str::trim) else {
                continue;
            };
            if region.is_empty() || !seen_regions.insert(region.to_string()) {
                continue;
            }
            if selected_keys.insert(agent.public_key.clone()) {
                selected.push(agent.clone());
            }
        }
        for public_key in &plan.providers {
            if selected.len() >= required {
                break;
            }
            let Some(agent) = agent_directory.get(public_key) else {
                continue;
            };
            if selected_keys.insert(agent.public_key.clone()) {
                selected.push(agent.clone());
            }
        }
        Ok(selected)
    }

    async fn execute_health_check_with_probe_agent(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &HealthCheckSpec,
        agent: &ConfiguredProbeAgent,
    ) -> Result<SignedHealthReceipt> {
        let issued_at = Utc::now();
        let expires_at = issued_at
            + chrono::Duration::milliseconds(spec.timeout_ms.saturating_add(2_000) as i64);
        let monitor_id = format!("health-check:{tx_hash}");
        let slot_key = "adhoc".to_string();
        let lease_id = compute_hash(&(
            chain_id.to_string(),
            tx_hash.to_string(),
            spec.request_id.clone(),
            self.address(),
            agent.public_key.clone(),
            "health-check-agent",
        ))?;
        let lease = self.wallet.sign_probe_agent_lease(SignedProbeAgentLease {
            id: String::new(),
            body: ProbeAgentLeaseBody {
                chain_id: chain_id.to_string(),
                lease_id,
                parent_validator: String::new(),
                agent_public_key: agent.public_key.clone(),
                monitor_id: monitor_id.clone(),
                slot_key: slot_key.clone(),
                request_id: spec.request_id.clone(),
                spec: spec.clone(),
                issued_at,
                expires_at,
                audit: false,
            },
            signature: String::new(),
        })?;
        let url = format!(
            "{}/v1/internal/agent/confirm",
            agent.endpoint.trim_end_matches('/')
        );
        let mut request = self
            .http_client
            .post(url)
            .timeout(Duration::from_millis(spec.timeout_ms.saturating_add(2_000)));
        if let Some(token) = agent.api_token.as_deref() {
            request = request.header(AUTHORIZATION, bearer_token_value(token));
        }
        let response = request.json(&lease).send().await?;
        if !response.status().is_success() {
            bail!("probe agent {} rejected lease", agent.public_key);
        }
        let payload = response.json::<AgentConfirmationResponse>().await?;
        let receipt = payload.delegated_receipt;
        verify_delegated_probe_receipt(&receipt)?;
        if receipt.body.chain_id != chain_id {
            bail!("probe agent receipt chain_id mismatch");
        }
        if receipt.body.monitor_id != monitor_id || receipt.body.slot_key != slot_key {
            bail!("probe agent receipt slot mismatch");
        }
        if receipt.body.parent_validator != self.address() {
            bail!("probe agent receipt parent validator mismatch");
        }
        if receipt.body.agent_public_key != agent.public_key {
            bail!("probe agent receipt agent_public_key mismatch");
        }
        if receipt.body.request_id.as_deref() != Some(spec.request_id.as_str()) {
            bail!("probe agent receipt request_id mismatch");
        }
        if receipt.body.lease_id.as_deref() != Some(lease.id.as_str()) {
            bail!("probe agent receipt lease_id mismatch");
        }
        self.sign_health_receipt_from_probe_result(
            chain_id,
            tx_hash,
            &spec.request_id,
            receipt.body.observed_at,
            HealthExecution {
                response_status: receipt.body.response_status,
                latency_ms: receipt.body.latency_ms,
                success: receipt.body.success,
                assertion_results: receipt.body.assertion_results,
                response_headers: receipt.body.response_headers,
                response_body_sample: receipt.body.response_body_sample,
                error: receipt.body.error,
            },
        )
    }

    fn sign_health_receipt_from_probe_result(
        &self,
        chain_id: &str,
        tx_hash: &str,
        request_id: &str,
        observed_at: DateTime<Utc>,
        outcome: HealthExecution,
    ) -> Result<SignedHealthReceipt> {
        self.wallet.sign_receipt(SignedHealthReceipt {
            id: String::new(),
            body: HealthReceiptBody {
                chain_id: chain_id.to_string(),
                tx_hash: tx_hash.to_string(),
                request_id: request_id.to_string(),
                executor: String::new(),
                observed_at,
                response_status: outcome.response_status,
                latency_ms: outcome.latency_ms,
                success: outcome.success,
                assertion_results: outcome.assertion_results,
                response_headers: outcome.response_headers,
                response_body_sample: outcome.response_body_sample,
                error: outcome.error,
            },
            signature: String::new(),
        })
    }

    async fn dispatch_probe_agent_leases(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
        agents: &[ConfiguredProbeAgent],
    ) -> Result<Vec<SignedDelegatedProbeReceipt>> {
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let mut spec = heartbeat
            .confirmation_probe
            .cloned()
            .ok_or_else(|| anyhow!("monitor is missing confirmation_probe"))?;
        let request_id = monitor_confirmation_request_id(&monitor.monitor_id, slot_key);
        spec.request_id = request_id.clone();
        let issued_at = Utc::now();
        let expires_at = issued_at
            + chrono::Duration::milliseconds(spec.timeout_ms.saturating_add(2_000) as i64);
        let futures = agents.iter().enumerate().map(|(index, agent)| {
            let mut spec = spec.clone();
            let chain_id = chain_id.to_string();
            let monitor_id = monitor.monitor_id.clone();
            let slot_key = slot_key.to_string();
            let request_id = request_id.clone();
            let agent = agent.clone();
            async move {
                spec.request_id = request_id.clone();
                let lease_id = compute_hash(&(
                    chain_id.clone(),
                    monitor_id.clone(),
                    slot_key.clone(),
                    request_id.clone(),
                    self.address(),
                    agent.public_key.clone(),
                    index,
                ))?;
                let lease = self.wallet.sign_probe_agent_lease(SignedProbeAgentLease {
                    id: String::new(),
                    body: ProbeAgentLeaseBody {
                        chain_id: chain_id.clone(),
                        lease_id: lease_id.clone(),
                        parent_validator: String::new(),
                        agent_public_key: agent.public_key.clone(),
                        monitor_id: monitor_id.clone(),
                        slot_key: slot_key.clone(),
                        request_id: request_id.clone(),
                        spec,
                        issued_at,
                        expires_at,
                        audit: false,
                    },
                    signature: String::new(),
                })?;
                let url = format!(
                    "{}/v1/internal/agent/confirm",
                    agent.endpoint.trim_end_matches('/')
                );
                let mut request = self.http_client.post(url).timeout(Duration::from_millis(
                    lease.body.spec.timeout_ms.saturating_add(2_000),
                ));
                if let Some(token) = agent.api_token.as_deref() {
                    request = request.header(AUTHORIZATION, bearer_token_value(token));
                }
                let response = request.json(&lease).send().await?;
                if !response.status().is_success() {
                    bail!("probe agent {} rejected lease", agent.public_key);
                }
                let payload = response.json::<AgentConfirmationResponse>().await?;
                let receipt = payload.delegated_receipt;
                verify_delegated_probe_receipt(&receipt)?;
                if receipt.body.chain_id != chain_id {
                    bail!("probe agent receipt chain_id mismatch");
                }
                if receipt.body.monitor_id != monitor_id || receipt.body.slot_key != slot_key {
                    bail!("probe agent receipt slot mismatch");
                }
                if receipt.body.parent_validator != self.address() {
                    bail!("probe agent receipt parent validator mismatch");
                }
                if receipt.body.agent_public_key != agent.public_key {
                    bail!("probe agent receipt agent_public_key mismatch");
                }
                if receipt.body.lease_id.as_deref() != Some(lease.id.as_str()) {
                    bail!("probe agent receipt lease_id mismatch");
                }
                if receipt.body.request_id.as_deref() != Some(request_id.as_str()) {
                    bail!("probe agent receipt request_id mismatch");
                }
                Ok::<_, anyhow::Error>(receipt)
            }
        });

        let mut receipts = Vec::new();
        for receipt in join_all(futures).await.into_iter().flatten() {
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn summarize_delegated_receipts_as_validator_receipt(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
        assigned_validator_count: usize,
        delegated_receipts: &[SignedDelegatedProbeReceipt],
    ) -> Result<Option<SignedHealthReceipt>> {
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let mut unique = Vec::new();
        let mut seen_agents = BTreeSet::new();
        let synthetic_request_id = monitor_confirmation_request_id(&monitor.monitor_id, slot_key);
        for receipt in delegated_receipts {
            verify_delegated_probe_receipt(receipt)?;
            if receipt.body.chain_id != chain_id {
                bail!("delegated confirmation receipt is for a different chain");
            }
            if receipt.body.monitor_id != monitor.monitor_id || receipt.body.slot_key != slot_key {
                bail!("delegated confirmation receipt slot mismatch");
            }
            if receipt.body.parent_validator != self.address() {
                bail!("delegated confirmation receipt parent validator mismatch");
            }
            if receipt.body.request_id.as_deref() != Some(synthetic_request_id.as_str()) {
                bail!("delegated confirmation receipt request_id mismatch");
            }
            if receipt
                .body
                .lease_id
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            {
                bail!("delegated confirmation receipt lease_id cannot be empty");
            }
            if seen_agents.insert(receipt.body.agent_public_key.clone()) {
                unique.push(receipt.clone());
            }
        }
        let required = required_local_agent_receipts(
            heartbeat.miss_policy,
            assigned_validator_count,
            unique.len(),
        );
        if required > 0 && unique.len() < required {
            return Ok(None);
        }
        let mut clusters = BTreeMap::<String, Vec<SignedDelegatedProbeReceipt>>::new();
        for receipt in &unique {
            let outcome_key = delegated_receipt_outcome_key(receipt)?;
            clusters
                .entry(outcome_key)
                .or_default()
                .push(receipt.clone());
        }
        let mut best_key = None;
        let mut best_len = 0usize;
        let mut tied = false;
        for (key, cluster) in &clusters {
            if cluster.len() > best_len {
                best_key = Some(key.clone());
                best_len = cluster.len();
                tied = false;
            } else if cluster.len() == best_len {
                tied = true;
            }
        }
        let Some(best_key) = best_key else {
            return Ok(None);
        };
        if tied {
            return Ok(None);
        }
        let winning_cluster = clusters.remove(&best_key).unwrap_or_default();
        if winning_cluster.len() * 2 <= unique.len() {
            return Ok(None);
        }
        let representative = winning_cluster
            .first()
            .ok_or_else(|| anyhow!("missing delegated confirmation representative"))?;
        Ok(Some(self.wallet.sign_receipt(SignedHealthReceipt {
            id: String::new(),
            body: HealthReceiptBody {
                chain_id: chain_id.to_string(),
                tx_hash: monitor_confirmation_tx_hash(&monitor.monitor_id, slot_key)?,
                request_id: synthetic_request_id,
                executor: String::new(),
                observed_at: representative.body.observed_at,
                response_status: representative.body.response_status,
                latency_ms: representative.body.latency_ms,
                success: representative.body.success,
                assertion_results: representative.body.assertion_results.clone(),
                response_headers: representative.body.response_headers.clone(),
                response_body_sample: representative.body.response_body_sample.clone(),
                error: representative.body.error.clone(),
            },
            signature: String::new(),
        })?))
    }

    async fn execute_monitor_confirmation_direct(
        &self,
        chain_id: &str,
        monitor: &MonitorRecord,
        slot_key: &str,
    ) -> Result<SignedHealthReceipt> {
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let mut spec = heartbeat
            .confirmation_probe
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("monitor is missing confirmation_probe"))?;
        spec.request_id = monitor_confirmation_request_id(&monitor.monitor_id, slot_key);
        let tx_hash = monitor_confirmation_tx_hash(&monitor.monitor_id, slot_key)?;
        let outcome = execute_health_check(&spec).await;
        self.wallet.sign_receipt(SignedHealthReceipt {
            id: String::new(),
            body: HealthReceiptBody {
                chain_id: chain_id.to_string(),
                tx_hash,
                request_id: spec.request_id,
                executor: String::new(),
                observed_at: Utc::now(),
                response_status: outcome.response_status,
                latency_ms: outcome.latency_ms,
                success: outcome.success,
                assertion_results: outcome.assertion_results,
                response_headers: outcome.response_headers,
                response_body_sample: outcome.response_body_sample,
                error: outcome.error,
            },
            signature: String::new(),
        })
    }

    async fn spawn_health_execution(&self, tx: SignedTransaction) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            let has_probe_agents = runtime
                .configured_probe_agents()
                .await
                .map(|agents| !agents.is_empty())
                .unwrap_or(false);
            let execution_mode = {
                let state = runtime.state.read().await;
                let already_executed = state
                    .receipts
                    .get(&tx.hash)
                    .map(|receipts| {
                        receipts
                            .iter()
                            .any(|receipt| receipt.body.executor == runtime.address())
                    })
                    .unwrap_or(false);
                if state.chain.is_finalized_health_check(&tx.hash)
                    || already_executed
                    || !state.chain.validators.contains(&runtime.address())
                {
                    None
                } else if !has_probe_agents {
                    Some(true)
                } else if let Ok(Some((plan, index_by_tx_hash))) =
                    runtime.pending_check_plan(&state.chain, &state.mempool)
                {
                    index_by_tx_hash.get(&tx.hash).and_then(|task_index| {
                        let assignment = plan.assignment_for_task(*task_index)?;
                        if !plan.provider_should_execute(&runtime.address(), *task_index) {
                            return None;
                        }
                        Some(validator_should_run_direct_probe(
                            &runtime.address(),
                            &assignment,
                        ))
                    })
                } else {
                    Some(true)
                }
            };
            let Some(direct_probe) = execution_mode else {
                return;
            };

            let TransactionKind::HealthCheck { spec } = tx.body.kind.clone() else {
                return;
            };

            match runtime
                .execute_health_check_receipt(&tx.body.chain_id, &tx.hash, &spec, direct_probe)
                .await
            {
                Ok(receipt) => {
                    if let Err(error) = runtime.accept_receipt(receipt, true).await {
                        warn!(?error, tx_hash = %tx.hash, "failed to submit health receipt");
                    }
                }
                Err(error) => warn!(?error, tx_hash = %tx.hash, "failed to create health receipt"),
            }
        });
    }

    async fn execute_health_check_receipt(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &HealthCheckSpec,
        direct_probe: bool,
    ) -> Result<SignedHealthReceipt> {
        if direct_probe {
            let outcome = execute_health_check(spec).await;
            return self.sign_health_receipt_from_probe_result(
                chain_id,
                tx_hash,
                &spec.request_id,
                Utc::now(),
                outcome,
            );
        }
        let agents = self.configured_probe_agents().await?;
        let selected = self.select_round_robin_agents(
            chain_id,
            &format!("health-check-agent:{tx_hash}:{}", spec.request_id),
            &format!("{tx_hash}:{}", spec.request_id),
            1,
            &agents,
        )?;
        let Some(agent) = selected.first() else {
            let outcome = execute_health_check(spec).await;
            return self.sign_health_receipt_from_probe_result(
                chain_id,
                tx_hash,
                &spec.request_id,
                Utc::now(),
                outcome,
            );
        };
        self.execute_health_check_with_probe_agent(chain_id, tx_hash, spec, agent)
            .await
    }

    async fn spawn_browser_execution(&self, tx: SignedTransaction) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            let has_probe_agents = runtime
                .configured_probe_agents()
                .await
                .map(|agents| !agents.is_empty())
                .unwrap_or(false);
            let execution_mode = {
                let state = runtime.state.read().await;
                let already_executed = state
                    .browser_receipts
                    .get(&tx.hash)
                    .map(|receipts| {
                        receipts
                            .iter()
                            .any(|receipt| receipt.body.executor == runtime.address())
                    })
                    .unwrap_or(false);
                if state.chain.is_finalized_health_check(&tx.hash)
                    || already_executed
                    || !state.chain.validators.contains(&runtime.address())
                {
                    None
                } else if !has_probe_agents {
                    Some(true)
                } else if let Ok(Some((plan, index_by_tx_hash))) =
                    runtime.pending_check_plan(&state.chain, &state.mempool)
                {
                    index_by_tx_hash.get(&tx.hash).and_then(|task_index| {
                        let assignment = plan.assignment_for_task(*task_index)?;
                        if !plan.provider_should_execute(&runtime.address(), *task_index) {
                            return None;
                        }
                        Some(validator_should_run_direct_probe(
                            &runtime.address(),
                            &assignment,
                        ))
                    })
                } else {
                    Some(true)
                }
            };
            let Some(direct_probe) = execution_mode else {
                return;
            };

            let TransactionKind::BrowserCheck { spec } = tx.body.kind.clone() else {
                return;
            };

            match runtime
                .execute_browser_check_receipt(
                    &tx.body.chain_id,
                    &tx.hash,
                    &spec,
                    None,
                    direct_probe,
                )
                .await
            {
                Ok(receipt) => {
                    if let Err(error) = runtime.accept_browser_receipt(receipt, true).await {
                        warn!(?error, tx_hash = %tx.hash, "failed to submit browser receipt");
                    }
                }
                Err(error) => {
                    warn!(?error, tx_hash = %tx.hash, "failed to create browser receipt");
                }
            }
        });
    }

    async fn spawn_compute_execution(&self, tx: SignedTransaction) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            let should_execute = {
                let state = runtime.state.read().await;
                state.chain.validators.contains(&runtime.address())
                    && !state.chain.is_finalized_health_check(&tx.hash)
                    && !state
                        .compute_receipts
                        .get(&tx.hash)
                        .map(|receipts| {
                            receipts
                                .iter()
                                .any(|receipt| receipt.body.executor == runtime.address())
                        })
                        .unwrap_or(false)
            };
            if !should_execute {
                return;
            }
            let TransactionKind::ComputeJob { spec } = tx.body.kind.clone() else {
                return;
            };
            match runtime
                .execute_compute_job_receipt(&tx.body.chain_id, &tx.hash, &spec)
                .await
            {
                Ok(receipt) => {
                    if let Err(error) = runtime.accept_compute_receipt(receipt, true).await {
                        warn!(?error, tx_hash = %tx.hash, "failed to submit compute receipt");
                    }
                }
                Err(error) => {
                    warn!(?error, tx_hash = %tx.hash, "failed to create compute receipt");
                }
            }
        });
    }

    async fn execute_compute_job_receipt(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &ComputeJobSpec,
    ) -> Result<SignedComputeReceipt> {
        let started = std::time::Instant::now();
        let job_hash = compute_job_hash(spec)?;
        let agents = self.configured_probe_agents().await?;
        let task_keys = spec
            .shards
            .iter()
            .map(|shard| shard.shard_id.clone())
            .collect::<Vec<_>>();
        let providers = agents
            .iter()
            .map(|agent| agent.public_key.clone())
            .collect::<Vec<_>>();
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::Compute,
            chain_id,
            &format!("compute:{tx_hash}:{}", spec.request_id),
            &providers,
            &task_keys,
            1,
            false,
        )?;
        let agent_directory = agents
            .iter()
            .map(|agent| (agent.public_key.clone(), agent.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut outputs = Vec::with_capacity(spec.shards.len());
        let mut assigned_agents = BTreeMap::new();
        for (index, shard) in spec.shards.iter().enumerate() {
            let selected_agent = plan
                .assignment_for_task(index)
                .and_then(|assignment| assignment.mandatory_providers.first().cloned())
                .and_then(|public_key| agent_directory.get(&public_key).cloned());
            let output = if let Some(agent) = selected_agent {
                assigned_agents.insert(shard.shard_id.clone(), agent.public_key.clone());
                match self
                    .execute_compute_shard_with_agent(
                        chain_id, tx_hash, spec, shard, &job_hash, &agent,
                    )
                    .await
                {
                    Ok(output) => output,
                    Err(error) => {
                        warn!(
                            ?error,
                            tx_hash,
                            shard_id = %shard.shard_id,
                            agent = %agent.public_key,
                            "compute agent failed shard; falling back to validator execution"
                        );
                        self.execute_compute_shard_locally(tx_hash, spec, shard)
                            .await?
                    }
                }
            } else {
                self.execute_compute_shard_locally(tx_hash, spec, shard)
                    .await?
            };
            outputs.push(output);
        }
        let reduction = reduce_compute_outputs(spec, &outputs);
        let success = reduction.is_ok() && outputs.iter().all(|output| output.success);
        let (reduced_output, error) = match reduction {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        self.wallet.sign_compute_receipt(SignedComputeReceipt {
            id: String::new(),
            body: ComputeReceiptBody {
                chain_id: chain_id.to_string(),
                tx_hash: tx_hash.to_string(),
                request_id: spec.request_id.clone(),
                executor: String::new(),
                observed_at: Utc::now(),
                job_hash,
                assigned_agents,
                shard_outputs: outputs,
                reduced_output,
                latency_ms,
                success,
                error,
            },
            signature: String::new(),
        })
    }

    async fn execute_compute_shard_with_agent(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &ComputeJobSpec,
        shard: &crate::compute::ComputeShardSpec,
        job_hash: &str,
        agent: &ConfiguredProbeAgent,
    ) -> Result<crate::compute::ComputeShardOutput> {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::seconds(spec.max_runtime_secs as i64 + 5);
        let lease_id = compute_hash(&(
            chain_id.to_string(),
            tx_hash.to_string(),
            spec.request_id.clone(),
            shard.shard_id.clone(),
            self.address(),
            agent.public_key.clone(),
            "compute-shard-agent",
        ))?;
        let lease = self
            .wallet
            .sign_compute_shard_lease(SignedComputeShardLease {
                id: String::new(),
                body: ComputeShardLeaseBody {
                    chain_id: chain_id.to_string(),
                    lease_id,
                    parent_validator: String::new(),
                    agent_public_key: agent.public_key.clone(),
                    tx_hash: tx_hash.to_string(),
                    request_id: spec.request_id.clone(),
                    job_hash: job_hash.to_string(),
                    workload: spec.workload.clone(),
                    reducer: spec.reducer.clone(),
                    max_runtime_secs: spec.max_runtime_secs,
                    sandbox: spec.sandbox.clone(),
                    artifact_policy: spec.artifact_policy.clone(),
                    shard: shard.clone(),
                    issued_at,
                    expires_at,
                    audit: false,
                },
                signature: String::new(),
            })?;
        verify_compute_shard_lease(&lease)?;
        let url = format!(
            "{}/v1/internal/agent/compute-shard",
            agent.endpoint.trim_end_matches('/')
        );
        let mut request = self
            .http_client
            .post(url)
            .timeout(Duration::from_secs(spec.max_runtime_secs + 5));
        if let Some(token) = agent.api_token.as_deref() {
            request = request.header(AUTHORIZATION, bearer_token_value(token));
        }
        let response = request.json(&lease).send().await?;
        if !response.status().is_success() {
            bail!("compute agent {} rejected shard lease", agent.public_key);
        }
        let payload = response.json::<AgentComputeResponse>().await?;
        let receipt = payload.delegated_receipt;
        verify_delegated_compute_shard_receipt(&receipt)?;
        if receipt.body.chain_id != chain_id {
            bail!("compute agent receipt chain_id mismatch");
        }
        if receipt.body.tx_hash != tx_hash {
            bail!("compute agent receipt tx_hash mismatch");
        }
        if receipt.body.request_id != spec.request_id {
            bail!("compute agent receipt request_id mismatch");
        }
        if receipt.body.job_hash != job_hash {
            bail!("compute agent receipt job_hash mismatch");
        }
        if receipt.body.parent_validator != self.address() {
            bail!("compute agent receipt parent validator mismatch");
        }
        if receipt.body.agent_public_key != agent.public_key {
            bail!("compute agent receipt agent_public_key mismatch");
        }
        if receipt.body.lease_id != lease.id {
            bail!("compute agent receipt lease_id mismatch");
        }
        if receipt.body.shard_output.shard_id != shard.shard_id {
            bail!("compute agent receipt shard_id mismatch");
        }
        let mut output = receipt.body.shard_output;
        self.mirror_compute_artifacts_from_agent(tx_hash, &mut output, agent)
            .await?;
        Ok(output)
    }

    async fn execute_compute_shard_locally(
        &self,
        tx_hash: &str,
        spec: &ComputeJobSpec,
        shard: &crate::compute::ComputeShardSpec,
    ) -> Result<crate::compute::ComputeShardOutput> {
        execute_compute_shard_isolated(
            spec,
            shard,
            tx_hash,
            &self.address(),
            &compute_sandbox_dir(&self.config.state_dir),
            &compute_artifact_dir(&self.config.state_dir),
        )
        .await
    }

    async fn mirror_compute_artifacts_from_agent(
        &self,
        tx_hash: &str,
        output: &mut crate::compute::ComputeShardOutput,
        agent: &ConfiguredProbeAgent,
    ) -> Result<()> {
        if output.artifacts.is_empty() {
            return Ok(());
        }
        let shard_id = output.shard_id.clone();
        for artifact in &mut output.artifacts {
            if artifact.provider != agent.public_key {
                bail!("compute agent artifact provider mismatch");
            }
            let url = format!(
                "{}/v1/internal/agent/compute-artifacts/{}/{}/{}",
                agent.endpoint.trim_end_matches('/'),
                tx_hash,
                shard_id,
                artifact.path
            );
            let mut request = self.http_client.get(url).timeout(Duration::from_secs(30));
            if let Some(token) = agent.api_token.as_deref() {
                request = request.header(AUTHORIZATION, bearer_token_value(token));
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                bail!("compute agent {} did not return artifact", agent.public_key);
            }
            let bytes = response.bytes().await?;
            if bytes.len() as u64 != artifact.size_bytes {
                bail!("compute agent artifact size mismatch");
            }
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            if hex::encode(hasher.finalize()) != artifact.sha256 {
                bail!("compute agent artifact hash mismatch");
            }
            let local_path = compute_artifact_path(
                &compute_artifact_dir(&self.config.state_dir),
                tx_hash,
                &shard_id,
                &artifact.path,
            )?;
            if let Some(parent) = local_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::write(&local_path, &bytes).await?;
            artifact.provider = self.address();
        }
        Ok(())
    }

    async fn spawn_monitor_browser_execution(&self, task: ScheduledBrowserTask) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            let Some((chain_id, tx_hash, spec, monitor_id, slot_key, direct_probe)) = ({
                let state = runtime.state.read().await;
                let monitor = match state.chain.monitors.get(&task.monitor.monitor_id).cloned() {
                    Some(monitor) => monitor,
                    None => return,
                };
                let package = match monitor.spec.browser_package().cloned() {
                    Some(package) => package,
                    None => return,
                };
                let tx_hash = match monitor_browser_tx_hash(&monitor.monitor_id, &task.slot_key) {
                    Ok(hash) => hash,
                    Err(_) => return,
                };
                let slot_status = state
                    .chain
                    .monitor_slot_history
                    .get(&monitor.monitor_id)
                    .and_then(|slots| slots.get(&task.slot_key))
                    .map(|slot| slot.status.clone());
                let terminal = matches!(
                    slot_status,
                    Some(
                        MonitorSlotStatus::Ok
                            | MonitorSlotStatus::RecoveredLate
                            | MonitorSlotStatus::MissedUnconfirmed
                            | MonitorSlotStatus::MissedServiceReachable
                            | MonitorSlotStatus::DownConfirmed
                            | MonitorSlotStatus::InsufficientFunds
                    )
                );
                let already_executed = state
                    .browser_receipts
                    .get(&tx_hash)
                    .map(|receipts| {
                        receipts
                            .iter()
                            .any(|receipt| receipt.body.executor == runtime.address())
                    })
                    .unwrap_or(false);
                let cost = match monitor_browser_slot_cost(&package) {
                    Ok(cost) => cost,
                    Err(_) => return,
                };
                if monitor.paused || terminal || already_executed || monitor.budget_balance < cost {
                    None
                } else {
                    let tasks = match pending_monitor_browser_tasks(&state.chain, Utc::now()) {
                        Ok(tasks) => tasks,
                        Err(_) => return,
                    };
                    let task_key = format!("{}:{}", monitor.monitor_id, task.slot_key);
                    let execution_mode = match runtime
                        .pending_monitor_browser_plan(&state.chain, &tasks)
                    {
                        Ok(Some((plan, index_by_task))) => {
                            index_by_task.get(&task_key).and_then(|task_index| {
                                let assignment = plan.assignment_for_task(*task_index)?;
                                if !plan.provider_should_execute(&runtime.address(), *task_index) {
                                    return None;
                                }
                                Some(validator_should_run_direct_probe(
                                    &runtime.address(),
                                    &assignment,
                                ))
                            })
                        }
                        Ok(None) => None,
                        Err(_) => return,
                    };
                    execution_mode.map(|direct_probe| {
                        (
                            state.chain.chain_id.clone(),
                            tx_hash,
                            BrowserCheckSpec {
                                request_id: monitor_browser_request_id(
                                    &monitor.monitor_id,
                                    &task.slot_key,
                                ),
                                package,
                            },
                            monitor.monitor_id.clone(),
                            task.slot_key.clone(),
                            direct_probe,
                        )
                    })
                }
            }) else {
                return;
            };

            match runtime
                .execute_browser_check_receipt(
                    &chain_id,
                    &tx_hash,
                    &spec,
                    Some((&monitor_id, &slot_key)),
                    direct_probe,
                )
                .await
            {
                Ok(receipt) => {
                    if let Err(error) = runtime.accept_browser_receipt(receipt, true).await {
                        warn!(
                            ?error,
                            monitor_id = %monitor_id,
                            slot_key = %slot_key,
                            "failed to submit scheduled browser receipt"
                        );
                    }
                }
                Err(error) => {
                    warn!(
                        ?error,
                        monitor_id = %monitor_id,
                        slot_key = %slot_key,
                        "failed to create scheduled browser receipt"
                    );
                }
            }
        });
    }

    async fn execute_browser_check_receipt(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &BrowserCheckSpec,
        monitor_context: Option<(&str, &str)>,
        direct_probe: bool,
    ) -> Result<SignedBrowserReceipt> {
        if direct_probe {
            let execution =
                execute_browser_check(spec, tx_hash, &self.browser_runner_config()).await?;
            return self.wallet.sign_browser_receipt(SignedBrowserReceipt {
                id: String::new(),
                body: BrowserReceiptBody {
                    chain_id: chain_id.to_string(),
                    tx_hash: tx_hash.to_string(),
                    request_id: spec.request_id.clone(),
                    monitor_id: monitor_context.map(|(monitor_id, _)| monitor_id.to_string()),
                    slot_key: monitor_context.map(|(_, slot_key)| slot_key.to_string()),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    package_hash: crate::browser::browser_package_hash(&spec.package)?,
                    runtime_hash: crate::browser::browser_runtime_hash(&spec.package.runtime)?,
                    latency_ms: execution.latency_ms,
                    success: execution.success,
                    failed_step_index: execution.failed_step_index,
                    final_url: execution.final_url,
                    outcome_class: execution.outcome_class,
                    console_error_count: execution.console_error_count,
                    network_error_count: execution.network_error_count,
                    screenshot_artifact: execution.screenshot_artifact,
                    trace_artifact: execution.trace_artifact,
                    video_artifact: execution.video_artifact,
                    error: execution.error,
                },
                signature: String::new(),
            });
        }
        let agents = self.configured_probe_agents().await?;
        let task_key = match monitor_context {
            Some((monitor_id, slot_key)) => {
                format!(
                    "browser-monitor:{monitor_id}:{slot_key}:{}",
                    spec.request_id
                )
            }
            None => format!("browser-check:{tx_hash}:{}", spec.request_id),
        };
        let selected = self.select_round_robin_agents(
            chain_id,
            &format!("browser-agent:{task_key}"),
            &task_key,
            1,
            &agents,
        )?;
        let Some(agent) = selected.first() else {
            let execution =
                execute_browser_check(spec, tx_hash, &self.browser_runner_config()).await?;
            return self.wallet.sign_browser_receipt(SignedBrowserReceipt {
                id: String::new(),
                body: BrowserReceiptBody {
                    chain_id: chain_id.to_string(),
                    tx_hash: tx_hash.to_string(),
                    request_id: spec.request_id.clone(),
                    monitor_id: monitor_context.map(|(monitor_id, _)| monitor_id.to_string()),
                    slot_key: monitor_context.map(|(_, slot_key)| slot_key.to_string()),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    package_hash: crate::browser::browser_package_hash(&spec.package)?,
                    runtime_hash: crate::browser::browser_runtime_hash(&spec.package.runtime)?,
                    latency_ms: execution.latency_ms,
                    success: execution.success,
                    failed_step_index: execution.failed_step_index,
                    final_url: execution.final_url,
                    outcome_class: execution.outcome_class,
                    console_error_count: execution.console_error_count,
                    network_error_count: execution.network_error_count,
                    screenshot_artifact: execution.screenshot_artifact,
                    trace_artifact: execution.trace_artifact,
                    video_artifact: execution.video_artifact,
                    error: execution.error,
                },
                signature: String::new(),
            });
        };
        self.execute_browser_check_with_probe_agent(chain_id, tx_hash, spec, agent, monitor_context)
            .await
    }

    fn browser_runner_config(&self) -> BrowserRunnerConfig {
        BrowserRunnerConfig {
            program: self.config.browser_runner_program.clone(),
            args: self.config.browser_runner_args.clone(),
            cache_dir: self
                .config
                .browser_cache_dir
                .clone()
                .unwrap_or_else(|| self.config.state_dir.join("browser_cache")),
            artifact_root: browser_artifact_dir(&self.config.state_dir),
            secret_store_path: self.config.browser_secret_store_path.clone(),
        }
    }

    async fn execute_browser_check_with_probe_agent(
        &self,
        chain_id: &str,
        tx_hash: &str,
        spec: &BrowserCheckSpec,
        agent: &ConfiguredProbeAgent,
        monitor_context: Option<(&str, &str)>,
    ) -> Result<SignedBrowserReceipt> {
        let issued_at = Utc::now();
        let expires_at =
            issued_at + chrono::Duration::seconds(spec.package.journey.max_runtime_secs as i64 + 5);
        let lease_id = compute_hash(&(
            chain_id.to_string(),
            tx_hash.to_string(),
            spec.request_id.clone(),
            self.address(),
            agent.public_key.clone(),
            monitor_context
                .map(|(monitor_id, slot_key)| format!("{monitor_id}:{slot_key}"))
                .unwrap_or_else(|| "adhoc".into()),
            "browser-agent",
        ))?;
        let lease = self
            .wallet
            .sign_browser_agent_lease(SignedBrowserAgentLease {
                id: String::new(),
                body: BrowserAgentLeaseBody {
                    chain_id: chain_id.to_string(),
                    lease_id,
                    parent_validator: String::new(),
                    agent_public_key: agent.public_key.clone(),
                    tx_hash: tx_hash.to_string(),
                    request_id: spec.request_id.clone(),
                    monitor_id: monitor_context.map(|(monitor_id, _)| monitor_id.to_string()),
                    slot_key: monitor_context.map(|(_, slot_key)| slot_key.to_string()),
                    spec: spec.clone(),
                    issued_at,
                    expires_at,
                    audit: false,
                },
                signature: String::new(),
            })?;
        verify_browser_agent_lease(&lease)?;
        let url = format!(
            "{}/v1/internal/agent/browser",
            agent.endpoint.trim_end_matches('/')
        );
        let mut request = self.http_client.post(url).timeout(Duration::from_secs(
            spec.package.journey.max_runtime_secs + 5,
        ));
        if let Some(token) = agent.api_token.as_deref() {
            request = request.header(AUTHORIZATION, bearer_token_value(token));
        }
        let response = request.json(&lease).send().await?;
        if !response.status().is_success() {
            bail!("probe agent {} rejected browser lease", agent.public_key);
        }
        let payload = response.json::<AgentBrowserResponse>().await?;
        let delegated_receipt = payload.delegated_receipt;
        verify_delegated_browser_receipt(&delegated_receipt)?;
        validate_delegated_browser_receipt(
            &delegated_receipt,
            chain_id,
            tx_hash,
            spec,
            &self.address(),
            &agent.public_key,
            &lease.id,
            monitor_context,
        )?;
        self.sign_browser_receipt_from_agent_result(chain_id, tx_hash, &delegated_receipt)
    }

    fn sign_browser_receipt_from_agent_result(
        &self,
        chain_id: &str,
        tx_hash: &str,
        delegated_receipt: &SignedDelegatedBrowserReceipt,
    ) -> Result<SignedBrowserReceipt> {
        self.wallet.sign_browser_receipt(SignedBrowserReceipt {
            id: String::new(),
            body: BrowserReceiptBody {
                chain_id: chain_id.to_string(),
                tx_hash: tx_hash.to_string(),
                request_id: delegated_receipt.body.request_id.clone(),
                monitor_id: delegated_receipt.body.monitor_id.clone(),
                slot_key: delegated_receipt.body.slot_key.clone(),
                executor: String::new(),
                observed_at: delegated_receipt.body.observed_at,
                package_hash: delegated_receipt.body.package_hash.clone(),
                runtime_hash: delegated_receipt.body.runtime_hash.clone(),
                latency_ms: delegated_receipt.body.latency_ms,
                success: delegated_receipt.body.success,
                failed_step_index: delegated_receipt.body.failed_step_index,
                final_url: delegated_receipt.body.final_url.clone(),
                outcome_class: delegated_receipt.body.outcome_class.clone(),
                console_error_count: delegated_receipt.body.console_error_count,
                network_error_count: delegated_receipt.body.network_error_count,
                screenshot_artifact: delegated_receipt.body.screenshot_artifact.clone(),
                trace_artifact: delegated_receipt.body.trace_artifact.clone(),
                video_artifact: delegated_receipt.body.video_artifact.clone(),
                error: delegated_receipt.body.error.clone(),
            },
            signature: String::new(),
        })
    }

    async fn replay_journal_events(&self, events: Vec<PersistedJournalEvent>) -> Result<()> {
        for event in events {
            match event {
                PersistedJournalEvent::TransactionAccepted { tx } => {
                    let mut state = self.state.write().await;
                    let _ = apply_transaction_to_state(&mut state, &self.address(), tx)?;
                }
                PersistedJournalEvent::ReceiptAccepted { receipt } => {
                    let mut state = self.state.write().await;
                    let _ = apply_receipt_to_state(&mut state, receipt)?;
                }
                PersistedJournalEvent::BrowserReceiptAccepted { receipt } => {
                    let mut state = self.state.write().await;
                    let _ = apply_browser_receipt_to_state(&mut state, receipt)?;
                }
                PersistedJournalEvent::ComputeReceiptAccepted { receipt } => {
                    let mut state = self.state.write().await;
                    let _ = apply_compute_receipt_to_state(&mut state, receipt)?;
                }
                PersistedJournalEvent::StorageProofReceiptAccepted { receipt } => {
                    let mut state = self.state.write().await;
                    let _ = apply_storage_proof_receipt_to_state(&mut state, receipt)?;
                }
                PersistedJournalEvent::HeartbeatObservationAccepted { observation } => {
                    let mut state = self.state.write().await;
                    let _ = apply_heartbeat_observation_to_state(&mut state, observation)?;
                }
                PersistedJournalEvent::ApprovalStored { approval } => {
                    let mut state = self.state.write().await;
                    let _ = apply_block_approval_to_state(&mut state, approval)?;
                }
                PersistedJournalEvent::ViewAdvanced {
                    active_view,
                    view_started_at,
                } => {
                    let mut state = self.state.write().await;
                    apply_view_advance_to_state(&mut state, active_view, view_started_at);
                }
                PersistedJournalEvent::BlockAccepted { block } => {
                    let finalized_records = {
                        let mut state = self.state.write().await;
                        apply_block_to_state(&mut state, block.clone())?
                    };
                    if let Some((
                        finalized_health_records,
                        finalized_browser_records,
                        finalized_compute_records,
                    )) = finalized_records
                    {
                        archive_block(&self.config.state_dir, &block).await?;
                        for record in &finalized_health_records {
                            archive_finalized_health_check(&self.config.state_dir, record).await?;
                        }
                        for record in &finalized_browser_records {
                            archive_finalized_browser_check(&self.config.state_dir, record).await?;
                        }
                        for record in &finalized_compute_records {
                            archive_finalized_compute_job(&self.config.state_dir, record).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn append_journal_event_locked(&self, event: &PersistedJournalEvent) -> Result<()> {
        append_journal_event(&self.config.state_dir, event).await
    }

    async fn persist_state_locked(&self) -> Result<()> {
        let state = self.state.read().await;
        let persisted = PersistedNodeState {
            chain: state.chain.clone(),
            finalized_blocks: BTreeMap::new(),
            mempool: state.mempool.clone(),
            receipts: state.receipts.clone(),
            browser_receipts: state.browser_receipts.clone(),
            compute_receipts: state.compute_receipts.clone(),
            storage_proof_receipts: state.storage_proof_receipts.clone(),
            heartbeat_observations: state.heartbeat_observations.clone(),
            heartbeat_client_nonces: state.heartbeat_client_nonces.clone(),
            block_approvals: state.block_approvals.clone(),
            delivered_alerts: state.delivered_alerts.clone(),
            active_view: state.active_view,
            view_started_at: state.view_started_at,
        };
        write_json_atomic(&self.config.state_dir.join("state.json"), &persisted).await?;
        Ok(())
    }

    async fn snapshot_and_compact_journal(&self) -> Result<()> {
        let _persist_guard = self.persist_lock.lock().await;
        self.snapshot_and_compact_journal_locked().await
    }

    async fn snapshot_and_compact_journal_locked(&self) -> Result<()> {
        self.persist_state_locked().await?;
        clear_journal_events(&self.config.state_dir).await
    }

    async fn broadcast<T: Serialize>(&self, path: &str, payload: &T) {
        let futures = self.config.peers.iter().map(|peer| async move {
            let url = format!("{}{}", peer.trim_end_matches('/'), path);
            let mut request = self.http_client.post(url);
            if let Some(token) = self.config.gossip_api_token.as_deref() {
                request = request.header(AUTHORIZATION, bearer_token_value(token));
            }
            match request.json(payload).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    warn!(status = ?response.status(), peer, "peer rejected gossip");
                }
                Err(error) => {
                    warn!(?error, peer, "failed to gossip to peer");
                }
            }
        });
        let _ = join_all(futures).await;
    }

    async fn quote_and_plan(&self, request: SwapQuoteRequest) -> Result<SwapExecutionPlan> {
        let state = self.state.read().await;
        if !state.chain.validators.contains(&self.address()) {
            bail!("only validator nodes may issue signed swap quotes");
        }
        let treasury_has_inventory =
            state.chain.spendable_balance(&state.chain.treasury) >= request.token_amount;
        match request.side {
            crate::protocol::SwapSide::Buy => {}
            crate::protocol::SwapSide::Sell => {
                if state.chain.spendable_balance(&request.wallet) < request.token_amount {
                    bail!("quoted wallet has insufficient spendable HT for this sell quote");
                }
            }
        }
        let mut quote = self.swap_registry.quote(&request).await?;
        quote.chain_id = state.chain.chain_id.clone();
        if request.side == crate::protocol::SwapSide::Buy && !treasury_has_inventory {
            quote.notes.push(
                "Treasury inventory is not currently reserved on-chain for this buy quote; treat it as an indicative OTC hand-off until inventory is provisioned."
                    .into(),
            );
        }
        drop(state);

        let signed_quote = self.wallet.sign_swap_quote(SignedSwapQuote {
            quote,
            quoted_by: String::new(),
            quoted_at: Utc::now(),
            signature: String::new(),
        })?;
        self.swap_registry.execution_plan(&signed_quote).await
    }

    async fn record_secret_ping(
        &self,
        monitor_id: String,
        token: String,
        signal: HeartbeatSignal,
        body: Bytes,
    ) -> Result<PingAcceptedResponse> {
        let monitor = {
            let state = self.state.read().await;
            state
                .chain
                .monitors
                .get(&monitor_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?
        };
        if monitor.paused {
            bail!("paused monitors do not accept heartbeat pings");
        }
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        if !signal_allowed(heartbeat.signal_policy, signal) {
            bail!("monitor does not accept this signal type");
        }
        let expected_hash = match heartbeat.ping_auth {
            HeartbeatAuth::SecretUrl { token_hash } => token_hash,
            HeartbeatAuth::Dual { token_hash, .. } => token_hash,
            HeartbeatAuth::DelegatedKey { .. } => {
                bail!("monitor requires delegated heartbeat signatures");
            }
        };
        if hash_secret_token(&token)? != *expected_hash {
            bail!("invalid heartbeat token");
        }

        self.record_heartbeat_observation(
            &monitor,
            signal,
            HeartbeatAuthMode::SecretUrl,
            body,
            None,
            None,
            None,
            None,
        )
        .await
    }

    async fn record_signed_ping(
        &self,
        monitor_id: String,
        signal: HeartbeatSignal,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<PingAcceptedResponse> {
        let monitor = {
            let state = self.state.read().await;
            state
                .chain
                .monitors
                .get(&monitor_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?
        };
        if monitor.paused {
            bail!("paused monitors do not accept heartbeat pings");
        }
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        if !signal_allowed(heartbeat.signal_policy, signal) {
            bail!("monitor does not accept this signal type");
        }

        let (expected_key_id, expected_public_key) = match heartbeat.ping_auth {
            HeartbeatAuth::DelegatedKey { key_id, public_key }
            | HeartbeatAuth::Dual {
                key_id, public_key, ..
            } => (key_id.as_str(), public_key.as_str()),
            HeartbeatAuth::SecretUrl { .. } => {
                bail!("monitor only supports secret-url heartbeat ingress");
            }
        };
        let key_id = required_header(headers, "x-ht-key-id")?;
        let signature = required_header(headers, "x-ht-signature")?;
        let nonce = required_header(headers, "x-ht-nonce")?;
        if nonce.len() > MAX_HEARTBEAT_NONCE_BYTES {
            bail!("heartbeat nonce exceeds maximum length");
        }
        if key_id != expected_key_id {
            bail!("heartbeat key id does not match this monitor");
        }
        let client_timestamp = parse_client_timestamp(required_header(headers, "x-ht-timestamp")?)?;
        let now = Utc::now();
        let skew = (now - client_timestamp).num_seconds().abs();
        if skew > MAX_CLIENT_CLOCK_SKEW_SECS {
            bail!("heartbeat timestamp is outside the accepted skew window");
        }
        let nonce_key = heartbeat_client_nonce_key(&monitor_id, nonce);
        {
            let state = self.state.read().await;
            if state.heartbeat_client_nonces.contains_key(&nonce_key) {
                bail!("heartbeat nonce has already been used for this monitor");
            }
        }

        let body_sha256 = digest_bytes_hex(&body);
        let message = canonical_heartbeat_client_message(
            &monitor_id,
            signal,
            client_timestamp,
            nonce,
            body_sha256.as_deref(),
        )?;
        verify_client_signature(expected_public_key, &message, signature)?;

        self.record_heartbeat_observation(
            &monitor,
            signal,
            HeartbeatAuthMode::DelegatedKey,
            body,
            Some(signature.to_string()),
            Some(key_id.to_string()),
            Some(client_timestamp),
            Some(nonce.to_string()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_heartbeat_observation(
        &self,
        monitor: &MonitorRecord,
        signal: HeartbeatSignal,
        auth_mode: HeartbeatAuthMode,
        body: Bytes,
        client_signature: Option<String>,
        client_key_id: Option<String>,
        client_timestamp: Option<DateTime<Utc>>,
        client_nonce: Option<String>,
    ) -> Result<PingAcceptedResponse> {
        let observed_at = Utc::now();
        let slot_key =
            schedule_current_slot_start(&monitor.spec.schedule, observed_at)?.to_rfc3339();
        let body_sha256 = digest_bytes_hex(&body);
        let body_sample = capture_body_sample(&monitor.spec.log_capture, &body);
        let observation = self
            .wallet
            .sign_heartbeat_observation(SignedHeartbeatObservation {
                id: String::new(),
                body: HeartbeatObservationBody {
                    chain_id: {
                        let state = self.state.read().await;
                        state.chain.chain_id.clone()
                    },
                    monitor_id: monitor.monitor_id.clone(),
                    slot_key: slot_key.clone(),
                    signal,
                    observed_at,
                    observed_by: String::new(),
                    body_sha256,
                    body_sample,
                    auth_mode,
                    client_signature,
                    client_key_id,
                    client_timestamp,
                    client_nonce,
                },
                signature: String::new(),
            })?;
        let accepted = self
            .accept_heartbeat_observation(observation.clone(), true)
            .await?;
        Ok(PingAcceptedResponse {
            accepted,
            monitor_id: monitor.monitor_id.clone(),
            slot_key,
            observation_id: observation.id,
        })
    }

    async fn account_response(&self, address: String) -> AccountResponse {
        let state = self.state.read().await;
        let account = state.chain.account(&address);
        AccountResponse {
            address,
            balance: account.balance,
            balance_display: crate::protocol::format_amount(account.balance),
            storage_balance: account.storage_balance,
            storage_balance_display: crate::protocol::format_amount(account.storage_balance),
            compute_balance: account.compute_balance,
            compute_balance_display: crate::protocol::format_amount(account.compute_balance),
            dns_balance: account.dns_balance,
            dns_balance_display: crate::protocol::format_amount(account.dns_balance),
            nonce: account.nonce,
            locked_balance: account.locked_balance,
        }
    }

    async fn ledger_snapshot(&self) -> LedgerSnapshot {
        let state = self.state.read().await;
        state.chain.snapshot()
    }

    async fn job_response(&self, tx_hash: String) -> JobResponse {
        let state = self.state.read().await;
        let finalized_health_record = state.chain.finalized_health_checks.get(&tx_hash).cloned();
        let finalized_browser_record = state.chain.finalized_browser_checks.get(&tx_hash).cloned();
        let finalized_compute_record = state.chain.finalized_compute_jobs.get(&tx_hash).cloned();
        let pending_health_receipts = state.receipts.get(&tx_hash).map(Vec::len).unwrap_or(0);
        let pending_browser_receipts = state
            .browser_receipts
            .get(&tx_hash)
            .map(Vec::len)
            .unwrap_or(0);
        let pending_compute_receipts = state
            .compute_receipts
            .get(&tx_hash)
            .map(Vec::len)
            .unwrap_or(0);
        let should_load_archived_health = finalized_health_record.is_none()
            && state.chain.finalized_health_check_ids.contains(&tx_hash);
        let should_load_archived_browser = finalized_browser_record.is_none()
            && state.chain.finalized_browser_check_ids.contains(&tx_hash);
        let should_load_archived_compute = finalized_compute_record.is_none()
            && state.chain.finalized_compute_job_ids.contains(&tx_hash);
        drop(state);
        let finalized_health_record = if should_load_archived_health {
            load_archived_finalized_health_check(&self.config.state_dir, &tx_hash)
                .await
                .ok()
                .flatten()
        } else {
            finalized_health_record
        };
        let finalized_browser_record = if should_load_archived_browser {
            load_archived_finalized_browser_check(&self.config.state_dir, &tx_hash)
                .await
                .ok()
                .flatten()
        } else {
            finalized_browser_record
        };
        let finalized_compute_record = if should_load_archived_compute {
            load_archived_finalized_compute_job(&self.config.state_dir, &tx_hash)
                .await
                .ok()
                .flatten()
        } else {
            finalized_compute_record
        };
        JobResponse {
            tx_hash,
            finalized: finalized_health_record.is_some()
                || finalized_browser_record.is_some()
                || finalized_compute_record.is_some(),
            finalized_record: finalized_health_record.clone(),
            finalized_health_record,
            finalized_browser_record,
            finalized_compute_record,
            pending_health_receipts,
            pending_browser_receipts,
            pending_compute_receipts,
        }
    }

    async fn swap_lock_response(&self, quote_id: String) -> SwapLockResponse {
        let state = self.state.read().await;
        let record = state.chain.pending_swap_locks.get(&quote_id).cloned();
        SwapLockResponse {
            quote_id,
            pending: record.is_some(),
            record,
        }
    }

    async fn storage_contract_response(
        &self,
        contract_id: String,
    ) -> Result<StorageContractResponse> {
        let state = self.state.read().await;
        let contract = state
            .chain
            .storage_contracts
            .get(&contract_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage contract {contract_id}"))?;
        Ok(StorageContractResponse { contract })
    }

    async fn compute_artifact_content_type(
        &self,
        tx_hash: &str,
        shard_id: &str,
        artifact_path: &str,
    ) -> Result<String> {
        let record = {
            let state = self.state.read().await;
            if let Some(record) = state.chain.finalized_compute_jobs.get(tx_hash) {
                Some(record.clone())
            } else if state.chain.finalized_compute_job_ids.contains(tx_hash) {
                None
            } else {
                bail!("unknown finalized compute job");
            }
        };
        let record = match record {
            Some(record) => record,
            None => load_archived_finalized_compute_job(&self.config.state_dir, tx_hash)
                .await?
                .ok_or_else(|| anyhow!("archived compute job is missing"))?,
        };
        let local_provider = self.address();
        record
            .rewarded_receipts
            .iter()
            .flat_map(|receipt| receipt.body.shard_outputs.iter())
            .filter(|output| output.shard_id == shard_id)
            .flat_map(|output| output.artifacts.iter())
            .find(|artifact| artifact.path == artifact_path && artifact.provider == local_provider)
            .map(|artifact| {
                artifact
                    .content_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string())
            })
            .ok_or_else(|| anyhow!("compute artifact is not available on this node"))
    }

    async fn domain_route_response(&self, host: String) -> Result<DomainRouteResponse> {
        let host = normalize_route_host(&host)?;
        let state = self.state.read().await;
        let now = Utc::now();
        let lease = state
            .chain
            .domain_leases
            .values()
            .find(|lease| {
                lease.fqdn == host
                    && matches!(lease.status, crate::protocol::DomainLeaseStatus::Active)
                    && lease.prepaid_balance > 0
                    && lease.expires_at > now
            })
            .cloned()
            .ok_or_else(|| anyhow!("unknown active domain route {host}"))?;
        let offering = state
            .chain
            .domain_offerings
            .get(&lease.offering_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown domain offering {}", lease.offering_id))?;
        if !matches!(
            offering.status,
            crate::protocol::DomainOfferingStatus::Active
        ) {
            bail!("domain offering is not active");
        }
        let contract = state
            .chain
            .storage_contracts
            .get(&lease.target_contract_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage contract {}", lease.target_contract_id))?;
        if !matches!(
            contract.spec.mode,
            crate::protocol::StorageMode::PublicRaw { .. }
        ) {
            bail!("domain route target is not public raw storage");
        }
        Ok(DomainRouteResponse {
            chain_id: state.chain.chain_id.clone(),
            offering,
            lease,
            contract,
        })
    }

    async fn status_response(&self) -> NodeStatusResponse {
        let state = self.state.read().await;
        NodeStatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_address: self.address(),
            chain_id: state.chain.chain_id.clone(),
            height: state.chain.height,
            last_block_hash: state.chain.last_block_hash.clone(),
            validator: state.chain.validators.contains(&self.address()),
            validator_count: state.chain.validators.len(),
            active_view: state.active_view,
            min_health_receipts: state.chain.min_health_receipts,
            block_approval_quorum: state.chain.required_block_approvals(),
            max_block_transactions: MAX_BLOCK_TRANSACTIONS,
            block_time_secs: state.chain.block_time_secs,
            mempool_size: state.mempool.len(),
            pending_receipt_count: state.receipts.values().map(Vec::len).sum::<usize>()
                + state.browser_receipts.values().map(Vec::len).sum::<usize>()
                + state.compute_receipts.values().map(Vec::len).sum::<usize>()
                + state
                    .heartbeat_observations
                    .values()
                    .map(Vec::len)
                    .sum::<usize>(),
            pending_swap_locks: state.chain.pending_swap_locks.len(),
            storage_contracts: state.chain.storage_contracts.len(),
            domain_offerings: state.chain.domain_offerings.len(),
            domain_leases: state.chain.domain_leases.len(),
            pending_storage_proof_receipts: state
                .storage_proof_receipts
                .values()
                .map(Vec::len)
                .sum(),
            finalized_health_checks: state.chain.finalized_health_check_count(),
            finalized_browser_checks: state.chain.finalized_browser_check_ids.len(),
            finalized_compute_jobs: state.chain.finalized_compute_job_ids.len(),
            control_api_auth_enabled: self.config.control_api_token.is_some(),
            gossip_api_auth_enabled: self.config.gossip_api_token.is_some(),
            peers: self.config.peers.clone(),
        }
    }

    async fn list_monitors_response(&self) -> MonitorListResponse {
        let state = self.state.read().await;
        MonitorListResponse {
            monitors: state.chain.monitors.values().cloned().collect(),
        }
    }

    async fn monitor_response(&self, monitor_id: String) -> Result<MonitorResponse> {
        let state = self.state.read().await;
        let monitor = state
            .chain
            .monitors
            .get(&monitor_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown monitor {monitor_id}"))?;
        Ok(MonitorResponse { monitor })
    }

    async fn monitor_slots_response(&self, monitor_id: String) -> Result<MonitorSlotsResponse> {
        let state = self.state.read().await;
        let slots = state
            .chain
            .monitor_slot_history
            .get(&monitor_id)
            .map(|items| items.values().cloned().collect())
            .unwrap_or_default();
        Ok(MonitorSlotsResponse { monitor_id, slots })
    }

    async fn monitor_alerts_response(&self, monitor_id: String) -> Result<MonitorAlertsResponse> {
        let state = self.state.read().await;
        let alerts = state
            .chain
            .alert_facts
            .values()
            .filter(|fact| fact.monitor_id == monitor_id)
            .cloned()
            .collect();
        Ok(MonitorAlertsResponse { monitor_id, alerts })
    }

    async fn finalized_block_at_height(&self, height: u64) -> Option<SignedBlock> {
        load_archived_block(&self.config.state_dir, height)
            .await
            .ok()
            .flatten()
    }

    async fn spawn_alert_delivery(&self, block: SignedBlock) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            let alerts = runtime.alert_facts_for_block(&block).await;
            if alerts.is_empty() {
                return;
            }
            if let Err(error) = runtime.deliver_alerts(alerts).await {
                warn!(?error, block_hash = %block.hash, "failed to deliver monitor alerts");
            }
        });
    }

    async fn alert_facts_for_block(&self, block: &SignedBlock) -> Vec<AlertFact> {
        let mut impacted_slots = BTreeSet::new();
        for observation in &block.body.heartbeat_observations {
            impacted_slots.insert((
                observation.body.monitor_id.clone(),
                observation.body.slot_key.clone(),
            ));
        }
        for evaluation in &block.body.monitor_evaluations {
            impacted_slots.insert((evaluation.monitor_id.clone(), evaluation.slot_key.clone()));
        }
        if impacted_slots.is_empty() {
            return Vec::new();
        }

        let state = self.state.read().await;
        state
            .chain
            .alert_facts
            .values()
            .filter(|fact| fact.created_at == block.body.proposed_at)
            .filter(|fact| {
                impacted_slots.contains(&(fact.monitor_id.clone(), fact.slot_key.clone()))
            })
            .cloned()
            .collect()
    }

    async fn deliver_alerts(&self, alerts: Vec<AlertFact>) -> Result<()> {
        let policies = self.load_notification_policies().await?;
        for alert in alerts {
            let Some(policy_id) = alert.notification_policy_id.clone() else {
                continue;
            };
            let Some(policy) = policies.policies.get(&policy_id) else {
                continue;
            };
            if policy.webhooks.is_empty() {
                continue;
            }

            let (chain_id, monitor, slot_record) = {
                let state = self.state.read().await;
                (
                    state.chain.chain_id.clone(),
                    state.chain.monitors.get(&alert.monitor_id).cloned(),
                    state
                        .chain
                        .monitor_slot_history
                        .get(&alert.monitor_id)
                        .and_then(|slots| slots.get(&alert.slot_key))
                        .cloned(),
                )
            };
            let payload = json!({
                "chain_id": chain_id,
                "alert": alert,
                "monitor": monitor,
                "slot": slot_record,
            });

            for webhook in &policy.webhooks {
                let delivery_key = alert_delivery_key(&alert.id, webhook)?;
                let already_delivered = {
                    let state = self.state.read().await;
                    state.delivered_alerts.contains_key(&delivery_key)
                };
                if already_delivered {
                    continue;
                }

                let mut request = self.http_client.post(&webhook.url);
                for (name, value) in &webhook.headers {
                    request = request.header(name, value);
                }
                request = request
                    .header("x-gossip-protocol-alert-id", &alert.id)
                    .header("x-gossip-protocol-policy-id", &policy_id);

                match request.json(&payload).send().await {
                    Ok(response) if response.status().is_success() => {
                        self.mark_alert_delivered(delivery_key).await?;
                    }
                    Ok(response) => {
                        warn!(
                            status = ?response.status(),
                            alert_id = %alert.id,
                            policy_id,
                            url = webhook.url,
                            "webhook delivery was rejected"
                        );
                    }
                    Err(error) => {
                        warn!(
                            ?error,
                            alert_id = %alert.id,
                            policy_id,
                            url = webhook.url,
                            "webhook delivery failed"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn load_notification_policies(&self) -> Result<NotificationPolicyStore> {
        let path = self
            .config
            .notification_policies_path
            .clone()
            .unwrap_or_else(|| self.config.state_dir.join("notification_policies.json"));
        Ok(read_json_optional(&path).await?.unwrap_or_default())
    }

    async fn mark_alert_delivered(&self, delivery_key: String) -> Result<()> {
        let _persist_guard = self.persist_lock.lock().await;
        {
            let mut state = self.state.write().await;
            state.delivered_alerts.insert(delivery_key, Utc::now());
        }
        self.persist_state_locked().await
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required header {name}"))
}

fn parse_client_timestamp(input: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(input)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| anyhow!("invalid heartbeat timestamp: {error}"))
}

fn parse_heartbeat_signal(
    signal: Option<&str>,
    headers: &HeaderMap,
) -> std::result::Result<HeartbeatSignal, (StatusCode, String)> {
    let raw = signal
        .or_else(|| {
            headers
                .get("x-ht-signal")
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("success");
    match raw.trim().to_ascii_lowercase().as_str() {
        "success" => Ok(HeartbeatSignal::Success),
        "start" => Ok(HeartbeatSignal::Start),
        "fail" => Ok(HeartbeatSignal::Fail),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported heartbeat signal {raw}"),
        )),
    }
}

fn capture_body_sample(policy: &LogCapturePolicy, body: &Bytes) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    match policy {
        LogCapturePolicy::None => None,
        LogCapturePolicy::CaptureText { max_bytes } => Some(truncate_capture(
            &String::from_utf8_lossy(body),
            (*max_bytes as usize).min(crate::protocol::MAX_PING_BODY_SAMPLE_BYTES),
        )),
    }
}

fn digest_bytes_hex(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(body);
    Some(hex::encode(hasher.finalize()))
}

fn signal_allowed(policy: &SignalPolicy, signal: HeartbeatSignal) -> bool {
    match policy {
        SignalPolicy::SuccessOnly => signal == HeartbeatSignal::Success,
        SignalPolicy::StartAndSuccess { .. } => {
            matches!(signal, HeartbeatSignal::Start | HeartbeatSignal::Success)
        }
        SignalPolicy::StartSuccessFail { .. } => true,
    }
}

fn expected_run_timeout_secs(policy: &SignalPolicy) -> Option<u64> {
    match policy {
        SignalPolicy::SuccessOnly => None,
        SignalPolicy::StartAndSuccess { run_timeout_secs }
        | SignalPolicy::StartSuccessFail { run_timeout_secs } => Some(*run_timeout_secs),
    }
}

fn validate_monitor_heartbeat_observation(
    monitor: &MonitorRecord,
    observation: &SignedHeartbeatObservation,
) -> Result<()> {
    let heartbeat = monitor
        .spec
        .heartbeat_config()
        .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
    if !signal_allowed(heartbeat.signal_policy, observation.body.signal) {
        bail!("heartbeat observation uses a signal not enabled for the monitor");
    }
    match (heartbeat.ping_auth, observation.body.auth_mode) {
        (HeartbeatAuth::SecretUrl { .. }, HeartbeatAuthMode::SecretUrl) => {}
        (HeartbeatAuth::DelegatedKey { key_id, public_key }, HeartbeatAuthMode::DelegatedKey)
        | (
            HeartbeatAuth::Dual {
                key_id, public_key, ..
            },
            HeartbeatAuthMode::DelegatedKey,
        ) => {
            let client_signature = observation
                .body
                .client_signature
                .as_deref()
                .ok_or_else(|| anyhow!("delegated heartbeat is missing client_signature"))?;
            let client_timestamp = observation
                .body
                .client_timestamp
                .ok_or_else(|| anyhow!("delegated heartbeat is missing client_timestamp"))?;
            let client_nonce = observation
                .body
                .client_nonce
                .as_deref()
                .ok_or_else(|| anyhow!("delegated heartbeat is missing client_nonce"))?;
            let client_key_id = observation
                .body
                .client_key_id
                .as_deref()
                .ok_or_else(|| anyhow!("delegated heartbeat is missing client_key_id"))?;
            if client_key_id != key_id {
                bail!("delegated heartbeat key_id mismatch");
            }
            let message = canonical_heartbeat_client_message(
                &observation.body.monitor_id,
                observation.body.signal,
                client_timestamp,
                client_nonce,
                observation.body.body_sha256.as_deref(),
            )?;
            verify_client_signature(public_key, &message, client_signature)?;
        }
        (HeartbeatAuth::Dual { .. }, HeartbeatAuthMode::SecretUrl) => {}
        _ => bail!("heartbeat auth mode does not match the monitor"),
    }
    Ok(())
}

fn verify_client_signature(
    public_key_base58: &str,
    message: &[u8],
    signature_base58: &str,
) -> Result<()> {
    let public_key_bytes = bs58::decode(public_key_base58)
        .into_vec()
        .context("failed to decode heartbeat public key")?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("heartbeat public key must decode to 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    let signature_bytes = bs58::decode(signature_base58)
        .into_vec()
        .context("failed to decode heartbeat signature")?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow!("heartbeat signature must decode to 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key.verify(message, &signature)?;
    Ok(())
}

fn monitor_effective_deadline(
    chain: &ChainState,
    monitor: &MonitorRecord,
    slot_started_at: DateTime<Utc>,
    pending_observations: Option<&[SignedHeartbeatObservation]>,
) -> Result<DateTime<Utc>> {
    let heartbeat = monitor
        .spec
        .heartbeat_config()
        .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
    let slot_key = slot_started_at.to_rfc3339();
    let mut deadline = chain
        .monitor_slot_history
        .get(&monitor.monitor_id)
        .and_then(|slots| slots.get(&slot_key))
        .map(|slot| slot.deadline_at)
        .unwrap_or_else(|| slot_deadline(slot_started_at, monitor.spec.grace_secs));

    if let Some(run_timeout_secs) = expected_run_timeout_secs(heartbeat.signal_policy)
        && let Some(started_at) = pending_observations.and_then(|items| {
            items
                .iter()
                .filter(|item| item.body.signal == HeartbeatSignal::Start)
                .map(|item| item.body.observed_at)
                .max()
        })
    {
        let extended = started_at + chrono::Duration::seconds(run_timeout_secs as i64);
        if extended > deadline {
            deadline = extended;
        }
    }

    Ok(deadline)
}

fn due_monitor_slot_starts(
    _chain: &ChainState,
    monitor: &MonitorRecord,
    proposed_at: DateTime<Utc>,
) -> Result<Vec<DateTime<Utc>>> {
    let Some(next_slot_hint) = monitor.next_slot_hint.as_deref() else {
        return Ok(Vec::new());
    };
    let next_slot = DateTime::parse_from_rfc3339(next_slot_hint)
        .map_err(|error| anyhow!("invalid next_slot_hint for {}: {error}", monitor.monitor_id))?
        .with_timezone(&Utc);
    let current_slot = schedule_current_slot_start(&monitor.spec.schedule, proposed_at)?;
    if next_slot > current_slot {
        return Ok(Vec::new());
    }

    let mut due = Vec::new();
    let mut cursor = next_slot;
    while cursor <= current_slot && due.len() < crate::protocol::MAX_CONFIRMATION_BATCHES {
        due.push(cursor);
        cursor = schedule_next_slot_start(&monitor.spec.schedule, cursor)?;
    }
    Ok(due)
}

fn pending_monitor_browser_tasks(
    chain: &ChainState,
    proposed_at: DateTime<Utc>,
) -> Result<Vec<ScheduledBrowserTask>> {
    let mut tasks = Vec::new();
    for monitor in chain.monitors.values() {
        if !monitor.spec.is_browser() || monitor.paused {
            continue;
        }
        let minimum_balance = monitor_minimum_slot_balance(&monitor.spec)?;
        if monitor.budget_balance < minimum_balance {
            continue;
        }
        for slot_started_at in due_monitor_slot_starts(chain, monitor, proposed_at)? {
            let slot_key = slot_started_at.to_rfc3339();
            let existing_status = chain
                .monitor_slot_history
                .get(&monitor.monitor_id)
                .and_then(|slots| slots.get(&slot_key))
                .map(|slot| slot.status.clone());
            let terminal = matches!(
                existing_status,
                Some(
                    MonitorSlotStatus::Ok
                        | MonitorSlotStatus::RecoveredLate
                        | MonitorSlotStatus::MissedUnconfirmed
                        | MonitorSlotStatus::MissedServiceReachable
                        | MonitorSlotStatus::DownConfirmed
                        | MonitorSlotStatus::InsufficientFunds
                )
            );
            if terminal {
                continue;
            }
            tasks.push(ScheduledBrowserTask {
                monitor: monitor.clone(),
                slot_key,
            });
        }
    }
    tasks.sort_by(|left, right| {
        left.slot_key
            .cmp(&right.slot_key)
            .then_with(|| left.monitor.monitor_id.cmp(&right.monitor.monitor_id))
    });
    Ok(tasks)
}

fn monitor_due_work_exists(
    chain: &ChainState,
    pending_browser_receipts: &BTreeMap<String, Vec<SignedBrowserReceipt>>,
    pending_observations: &BTreeMap<String, Vec<SignedHeartbeatObservation>>,
    proposed_at: DateTime<Utc>,
) -> Result<bool> {
    if pending_observations.values().any(|items| !items.is_empty()) {
        return Ok(true);
    }
    for monitor in chain.monitors.values() {
        let minimum_balance = monitor_minimum_slot_balance(&monitor.spec)?;
        for slot_started_at in due_monitor_slot_starts(chain, monitor, proposed_at)? {
            let slot_key = slot_started_at.to_rfc3339();
            let existing_status = chain
                .monitor_slot_history
                .get(&monitor.monitor_id)
                .and_then(|slots| slots.get(&slot_key))
                .map(|slot| slot.status.clone());
            let terminal = matches!(
                existing_status,
                Some(
                    MonitorSlotStatus::Ok
                        | MonitorSlotStatus::RecoveredLate
                        | MonitorSlotStatus::MissedUnconfirmed
                        | MonitorSlotStatus::MissedServiceReachable
                        | MonitorSlotStatus::DownConfirmed
                        | MonitorSlotStatus::InsufficientFunds
                )
            );
            if monitor.spec.is_browser() {
                let synthetic_tx_hash = monitor_browser_tx_hash(&monitor.monitor_id, &slot_key)?;
                let deadline = slot_deadline(slot_started_at, monitor.spec.grace_secs);
                let has_receipts = pending_browser_receipts
                    .get(&synthetic_tx_hash)
                    .map(|items| !items.is_empty())
                    .unwrap_or(false);
                if !monitor.paused && !terminal && (has_receipts || proposed_at > deadline) {
                    return Ok(true);
                }
            } else {
                let pending_key = heartbeat_slot_key(&monitor.monitor_id, &slot_key);
                let slot_pending = pending_observations.get(&pending_key);
                let deadline = monitor_effective_deadline(
                    chain,
                    monitor,
                    slot_started_at,
                    slot_pending.map(Vec::as_slice),
                )?;
                let has_success = slot_pending
                    .map(|items| {
                        items
                            .iter()
                            .any(|item| item.body.signal == HeartbeatSignal::Success)
                    })
                    .unwrap_or(false);
                if !monitor.paused && !terminal && !has_success && proposed_at > deadline {
                    return Ok(true);
                }
            }
        }
        if !monitor.paused && monitor.budget_balance < minimum_balance {
            return Ok(true);
        }
    }
    Ok(false)
}

fn heartbeat_client_nonce_key(monitor_id: &str, nonce: &str) -> String {
    format!("{monitor_id}:{nonce}")
}

fn prune_client_nonces(state: &mut RuntimeState, now: DateTime<Utc>) {
    let cutoff = now - chrono::Duration::seconds(CLIENT_NONCE_RETENTION_SECS);
    state
        .heartbeat_client_nonces
        .retain(|_, timestamp| *timestamp >= cutoff);
}

fn alert_delivery_key(alert_id: &str, webhook: &WebhookDestination) -> Result<String> {
    let destination_id = webhook
        .id
        .clone()
        .unwrap_or(crate::protocol::compute_hash(&(
            webhook.url.clone(),
            webhook.kind.clone(),
        ))?);
    Ok(format!("{alert_id}:{destination_id}"))
}

fn monitor_confirmation_tx_hash(monitor_id: &str, slot_key: &str) -> Result<String> {
    crate::protocol::compute_hash(&(monitor_id.to_string(), slot_key.to_string(), "confirmation"))
}

fn monitor_confirmation_request_id(monitor_id: &str, slot_key: &str) -> String {
    format!("monitor-confirmation:{monitor_id}:{slot_key}")
}

fn direct_validator_for_addresses(addresses: &[Address]) -> Option<Address> {
    addresses.iter().min().cloned()
}

fn direct_probe_executor_for_assignment(
    assignment: &crate::scheduler::TaskAssignment,
) -> Option<&str> {
    assignment.audit_provider.as_deref().or_else(|| {
        assignment
            .mandatory_providers
            .iter()
            .min()
            .map(String::as_str)
    })
}

fn validator_should_run_direct_probe(
    validator: &str,
    assignment: &crate::scheduler::TaskAssignment,
) -> bool {
    direct_probe_executor_for_assignment(assignment) == Some(validator)
}

fn required_confirmation_execution_agents(
    policy: &MissPolicy,
    assigned_validator_count: usize,
    available_agents: usize,
    direct_probe: bool,
) -> usize {
    if available_agents == 0 || assigned_validator_count == 0 {
        return 0;
    }
    match policy {
        MissPolicy::RecordOnly => 0,
        MissPolicy::ConfirmWithValidators { .. } => {
            if direct_probe {
                0
            } else {
                1.min(available_agents)
            }
        }
        MissPolicy::ConfirmWithDelegatedAgents { .. } => {
            required_local_agent_receipts(policy, assigned_validator_count, available_agents)
                .max(1)
                .min(available_agents)
        }
    }
}

#[derive(Serialize)]
struct DelegatedConsensusAssertionView<'a> {
    assertion: &'a crate::protocol::ResponseAssertion,
    passed: bool,
}

#[derive(Serialize)]
struct DelegatedConsensusReceiptView<'a> {
    success: bool,
    response_status: Option<u16>,
    error: Option<String>,
    assertion_results: Vec<DelegatedConsensusAssertionView<'a>>,
}

fn delegated_receipt_outcome_key(receipt: &SignedDelegatedProbeReceipt) -> Result<String> {
    let assertion_results = receipt
        .body
        .assertion_results
        .iter()
        .map(|result| DelegatedConsensusAssertionView {
            assertion: &result.assertion,
            passed: result.passed,
        })
        .collect();
    compute_hash(&DelegatedConsensusReceiptView {
        success: receipt.body.success,
        response_status: receipt.body.response_status,
        error: normalize_confirmation_error(receipt.body.error.as_deref()),
        assertion_results,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_delegated_browser_receipt(
    receipt: &SignedDelegatedBrowserReceipt,
    chain_id: &str,
    tx_hash: &str,
    spec: &BrowserCheckSpec,
    parent_validator: &str,
    agent_public_key: &str,
    lease_id: &str,
    monitor_context: Option<(&str, &str)>,
) -> Result<()> {
    if receipt.body.chain_id != chain_id {
        bail!("delegated browser receipt chain_id mismatch");
    }
    if receipt.body.tx_hash != tx_hash {
        bail!("delegated browser receipt tx_hash mismatch");
    }
    if receipt.body.parent_validator != parent_validator {
        bail!("delegated browser receipt parent validator mismatch");
    }
    if receipt.body.agent_public_key != agent_public_key {
        bail!("delegated browser receipt agent_public_key mismatch");
    }
    if receipt.body.request_id != spec.request_id {
        bail!("delegated browser receipt request_id mismatch");
    }
    if receipt.body.lease_id.as_deref() != Some(lease_id) {
        bail!("delegated browser receipt lease_id mismatch");
    }
    if receipt.body.package_hash != crate::browser::browser_package_hash(&spec.package)? {
        bail!("delegated browser receipt package_hash mismatch");
    }
    if receipt.body.runtime_hash != crate::browser::browser_runtime_hash(&spec.package.runtime)? {
        bail!("delegated browser receipt runtime_hash mismatch");
    }
    match monitor_context {
        Some((monitor_id, slot_key)) => {
            if receipt.body.monitor_id.as_deref() != Some(monitor_id) {
                bail!("delegated browser receipt monitor_id mismatch");
            }
            if receipt.body.slot_key.as_deref() != Some(slot_key) {
                bail!("delegated browser receipt slot_key mismatch");
            }
        }
        None => {
            if receipt.body.monitor_id.is_some() || receipt.body.slot_key.is_some() {
                bail!("delegated browser receipt monitor metadata is unexpected");
            }
        }
    }
    Ok(())
}

fn normalize_confirmation_error(error: Option<&str>) -> Option<String> {
    let text = error?.trim().to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        Some("timeout".into())
    } else if text.contains("dns") || text.contains("resolve") {
        Some("dns".into())
    } else if text.contains("connection") || text.contains("connect") {
        Some("connection".into())
    } else {
        Some(text)
    }
}

fn default_true() -> bool {
    true
}

fn apply_transaction_to_state(
    state: &mut RuntimeState,
    local_address: &str,
    tx: SignedTransaction,
) -> Result<ApplyTransactionResult> {
    let was_empty = state.mempool.is_empty()
        && state.storage_proof_receipts.is_empty()
        && state.compute_receipts.is_empty()
        && state.heartbeat_observations.is_empty();
    if state.seen_txs.contains(&tx.hash)
        || state.chain.is_finalized_health_check(&tx.hash)
        || state.mempool.contains_key(&tx.hash)
    {
        return Ok(ApplyTransactionResult {
            accepted: false,
            should_execute: false,
        });
    }
    state.chain.validate_transaction_basic(&tx)?;
    if state
        .mempool
        .values()
        .any(|existing| existing.signer == tx.signer && existing.body.nonce == tx.body.nonce)
    {
        bail!("another pending transaction already uses this signer nonce");
    }
    state.seen_txs.insert(tx.hash.clone());
    state.mempool.insert(tx.hash.clone(), tx.clone());
    if was_empty {
        state.active_view = 0;
        state.view_started_at = Utc::now();
    }
    Ok(ApplyTransactionResult {
        accepted: true,
        should_execute: matches!(
            tx.body.kind,
            TransactionKind::HealthCheck { .. }
                | TransactionKind::BrowserCheck { .. }
                | TransactionKind::ComputeJob { .. }
        ) && state
            .chain
            .validators
            .iter()
            .any(|validator| validator == local_address),
    })
}

fn apply_receipt_to_state(state: &mut RuntimeState, receipt: SignedHealthReceipt) -> Result<bool> {
    if state.seen_receipts.contains(&receipt.id)
        || state.chain.is_finalized_health_check(&receipt.body.tx_hash)
    {
        return Ok(false);
    }
    if receipt.body.chain_id != state.chain.chain_id {
        bail!("receipt is for a different chain");
    }
    if !state.chain.validators.contains(&receipt.body.executor) {
        bail!("receipt signer is not a validator");
    }
    crate::wallet::verify_receipt(&receipt)?;
    if let Some(tx) = state.mempool.get(&receipt.body.tx_hash) {
        match &tx.body.kind {
            TransactionKind::HealthCheck { spec } => {
                if receipt.body.request_id != spec.request_id {
                    bail!("receipt request_id does not match the pending health check");
                }
            }
            TransactionKind::Transfer { .. }
            | TransactionKind::StorageTransfer { .. }
            | TransactionKind::ComputeTransfer { .. }
            | TransactionKind::DnsTransfer { .. }
            | TransactionKind::BrowserCheck { .. }
            | TransactionKind::ComputeJob { .. }
            | TransactionKind::SwapLock { .. }
            | TransactionKind::SwapCancel { .. }
            | TransactionKind::SwapSettle { .. }
            | TransactionKind::MonitorCreate { .. }
            | TransactionKind::MonitorUpdate { .. }
            | TransactionKind::MonitorPause { .. }
            | TransactionKind::MonitorResume { .. }
            | TransactionKind::MonitorTopUp { .. }
            | TransactionKind::MonitorDelete { .. }
            | TransactionKind::StorageCreate { .. }
            | TransactionKind::StorageTopUp { .. }
            | TransactionKind::StorageCancel { .. }
            | TransactionKind::DomainOfferingCreate { .. }
            | TransactionKind::DomainOfferingPause { .. }
            | TransactionKind::DomainOfferingResume { .. }
            | TransactionKind::DomainOfferingRetire { .. }
            | TransactionKind::DomainLeaseCreate { .. }
            | TransactionKind::DomainLeaseRenew { .. }
            | TransactionKind::DomainLeaseBind { .. }
            | TransactionKind::DomainLeaseCancel { .. } => {
                bail!("receipts are only valid for health check transactions");
            }
        }
    }

    let already_seen_executor = state
        .receipts
        .get(&receipt.body.tx_hash)
        .map(|receipts| {
            receipts
                .iter()
                .any(|existing| existing.body.executor == receipt.body.executor)
        })
        .unwrap_or(false);
    if already_seen_executor {
        return Ok(false);
    }

    state.seen_receipts.insert(receipt.id.clone());
    state
        .receipts
        .entry(receipt.body.tx_hash.clone())
        .or_default()
        .push(receipt);
    Ok(true)
}

fn apply_browser_receipt_to_state(
    state: &mut RuntimeState,
    receipt: SignedBrowserReceipt,
) -> Result<bool> {
    if state.seen_browser_receipts.contains(&receipt.id)
        || state.chain.is_finalized_health_check(&receipt.body.tx_hash)
    {
        return Ok(false);
    }
    if receipt.body.chain_id != state.chain.chain_id {
        bail!("browser receipt is for a different chain");
    }
    if !state.chain.validators.contains(&receipt.body.executor) {
        bail!("browser receipt signer is not a validator");
    }
    crate::wallet::verify_browser_receipt(&receipt)?;
    if let Some(tx) = state.mempool.get(&receipt.body.tx_hash) {
        match &tx.body.kind {
            TransactionKind::BrowserCheck { spec } => {
                if receipt.body.request_id != spec.request_id {
                    bail!("browser receipt request_id does not match the pending browser check");
                }
                if receipt.body.package_hash != crate::browser::browser_package_hash(&spec.package)?
                {
                    bail!("browser receipt package_hash does not match the pending browser check");
                }
                if receipt.body.runtime_hash
                    != crate::browser::browser_runtime_hash(&spec.package.runtime)?
                {
                    bail!("browser receipt runtime_hash does not match the pending browser check");
                }
                if receipt.body.monitor_id.is_some() || receipt.body.slot_key.is_some() {
                    bail!("ad hoc browser receipts may not include monitor metadata");
                }
            }
            _ => {
                bail!("browser receipts are only valid for browser check transactions");
            }
        }
    } else if let (Some(monitor_id), Some(slot_key)) = (
        receipt.body.monitor_id.as_deref(),
        receipt.body.slot_key.as_deref(),
    ) {
        let monitor = state
            .chain
            .monitors
            .get(monitor_id)
            .cloned()
            .ok_or_else(|| anyhow!("browser receipt references an unknown monitor"))?;
        let package = monitor
            .spec
            .browser_package()
            .ok_or_else(|| anyhow!("browser receipt monitor is not a browser monitor"))?;
        if receipt.body.tx_hash != monitor_browser_tx_hash(monitor_id, slot_key)? {
            bail!("browser receipt tx_hash does not match the monitor slot");
        }
        if receipt.body.request_id != monitor_browser_request_id(monitor_id, slot_key) {
            bail!("browser receipt request_id does not match the monitor slot");
        }
        if receipt.body.package_hash != crate::browser::browser_package_hash(package)? {
            bail!("browser receipt package_hash does not match the browser monitor");
        }
        if receipt.body.runtime_hash != crate::browser::browser_runtime_hash(&package.runtime)? {
            bail!("browser receipt runtime_hash does not match the browser monitor");
        }
        let existing_status = state
            .chain
            .monitor_slot_history
            .get(monitor_id)
            .and_then(|slots| slots.get(slot_key))
            .map(|slot| slot.status.clone());
        if matches!(
            existing_status,
            Some(
                MonitorSlotStatus::Ok
                    | MonitorSlotStatus::RecoveredLate
                    | MonitorSlotStatus::MissedUnconfirmed
                    | MonitorSlotStatus::MissedServiceReachable
                    | MonitorSlotStatus::DownConfirmed
                    | MonitorSlotStatus::InsufficientFunds
            )
        ) {
            return Ok(false);
        }
    } else {
        bail!("browser receipt does not reference a pending browser transaction or monitor slot");
    }

    let already_seen_executor = state
        .browser_receipts
        .get(&receipt.body.tx_hash)
        .map(|receipts| {
            receipts
                .iter()
                .any(|existing| existing.body.executor == receipt.body.executor)
        })
        .unwrap_or(false);
    if already_seen_executor {
        return Ok(false);
    }

    state.seen_browser_receipts.insert(receipt.id.clone());
    state
        .browser_receipts
        .entry(receipt.body.tx_hash.clone())
        .or_default()
        .push(receipt);
    Ok(true)
}

fn apply_compute_receipt_to_state(
    state: &mut RuntimeState,
    receipt: SignedComputeReceipt,
) -> Result<bool> {
    if state.seen_compute_receipts.contains(&receipt.id)
        || state.chain.is_finalized_health_check(&receipt.body.tx_hash)
    {
        return Ok(false);
    }
    if receipt.body.chain_id != state.chain.chain_id {
        bail!("compute receipt is for a different chain");
    }
    if !state.chain.validators.contains(&receipt.body.executor) {
        bail!("compute receipt signer is not a validator");
    }
    crate::wallet::verify_compute_receipt(&receipt)?;
    if let Some(tx) = state.mempool.get(&receipt.body.tx_hash) {
        let TransactionKind::ComputeJob { spec } = &tx.body.kind else {
            bail!("compute receipts are only valid for compute job transactions");
        };
        if receipt.body.request_id != spec.request_id {
            bail!("compute receipt request_id does not match the pending compute job");
        }
        if receipt.body.job_hash != compute_job_hash(spec)? {
            bail!("compute receipt job_hash does not match the pending compute job");
        }
    } else {
        bail!("compute receipt does not reference a pending compute transaction");
    }

    let already_seen_executor = state
        .compute_receipts
        .get(&receipt.body.tx_hash)
        .map(|receipts| {
            receipts
                .iter()
                .any(|existing| existing.body.executor == receipt.body.executor)
        })
        .unwrap_or(false);
    if already_seen_executor {
        return Ok(false);
    }

    state.seen_compute_receipts.insert(receipt.id.clone());
    state
        .compute_receipts
        .entry(receipt.body.tx_hash.clone())
        .or_default()
        .push(receipt);
    Ok(true)
}

fn apply_storage_proof_receipt_to_state(
    state: &mut RuntimeState,
    receipt: SignedStorageProofReceipt,
) -> Result<bool> {
    let was_empty = state.mempool.is_empty()
        && state.storage_proof_receipts.is_empty()
        && state.heartbeat_observations.is_empty();
    if state.seen_storage_proof_receipts.contains(&receipt.id) {
        return Ok(false);
    }
    if receipt.body.chain_id != state.chain.chain_id {
        bail!("storage proof receipt is for a different chain");
    }
    if !state.chain.validators.contains(&receipt.body.validator) {
        bail!("storage proof receipt signer is not a validator");
    }
    crate::wallet::verify_storage_proof_receipt(&receipt)?;
    let contract = state
        .chain
        .storage_contracts
        .get(&receipt.body.contract_id)
        .ok_or_else(|| anyhow!("storage proof references an unknown contract"))?;
    if !matches!(
        contract.status,
        crate::protocol::StorageContractStatus::Active
    ) {
        bail!("storage proof references an inactive contract");
    }
    if receipt.body.host != contract.host {
        bail!("storage proof host does not match the contract");
    }
    if receipt.body.window_start != contract.last_proven_at {
        bail!("storage proof window_start does not match the contract");
    }
    if receipt.body.window_end <= receipt.body.window_start {
        bail!("storage proof window is invalid");
    }
    if receipt.body.window_end > Utc::now() {
        bail!("storage proof receipt is from the future");
    }

    let key = storage_proof_window_key(
        &receipt.body.contract_id,
        receipt.body.window_start,
        receipt.body.window_end,
    );
    let already_seen_validator = state
        .storage_proof_receipts
        .get(&key)
        .map(|receipts| {
            receipts
                .iter()
                .any(|existing| existing.body.validator == receipt.body.validator)
        })
        .unwrap_or(false);
    if already_seen_validator {
        return Ok(false);
    }

    state.seen_storage_proof_receipts.insert(receipt.id.clone());
    state
        .storage_proof_receipts
        .entry(key)
        .or_default()
        .push(receipt);
    if was_empty {
        state.active_view = 0;
        state.view_started_at = Utc::now();
    }
    Ok(true)
}

fn apply_heartbeat_observation_to_state(
    state: &mut RuntimeState,
    observation: SignedHeartbeatObservation,
) -> Result<bool> {
    if state.seen_heartbeat_observations.contains(&observation.id) {
        return Ok(false);
    }
    if observation.body.chain_id != state.chain.chain_id {
        bail!("heartbeat observation is for a different chain");
    }
    verify_heartbeat_observation(&observation)?;
    let monitor = state
        .chain
        .monitors
        .get(&observation.body.monitor_id)
        .cloned()
        .ok_or_else(|| anyhow!("heartbeat observation references an unknown monitor"))?;
    validate_monitor_heartbeat_observation(&monitor, &observation)?;
    if monitor.paused {
        bail!("paused monitors do not accept heartbeat pings");
    }
    if let Some(nonce) = observation.body.client_nonce.as_deref() {
        let key = heartbeat_client_nonce_key(&observation.body.monitor_id, nonce);
        if state.heartbeat_client_nonces.contains_key(&key) {
            bail!("heartbeat nonce has already been used for this monitor");
        }
        let timestamp = observation
            .body
            .client_timestamp
            .unwrap_or(observation.body.observed_at);
        state.heartbeat_client_nonces.insert(key, timestamp);
    }
    let key = heartbeat_slot_key(&observation.body.monitor_id, &observation.body.slot_key);
    if let Some(slot_record) = state
        .chain
        .monitor_slot_history
        .get(&observation.body.monitor_id)
        .and_then(|slots| slots.get(&observation.body.slot_key))
        && matches!(
            (slot_record.status.clone(), observation.body.signal),
            (MonitorSlotStatus::Ok, HeartbeatSignal::Success)
                | (MonitorSlotStatus::Running, HeartbeatSignal::Start)
                | (MonitorSlotStatus::RecoveredLate, HeartbeatSignal::Success)
                | (MonitorSlotStatus::FailedExplicit, HeartbeatSignal::Fail)
        )
    {
        return Ok(false);
    }
    if state
        .heartbeat_observations
        .get(&key)
        .map(|items| {
            items
                .iter()
                .any(|item| item.body.signal == observation.body.signal)
        })
        .unwrap_or(false)
    {
        return Ok(false);
    }
    state
        .seen_heartbeat_observations
        .insert(observation.id.clone());
    state
        .heartbeat_observations
        .entry(key)
        .or_default()
        .push(observation);
    Ok(true)
}

fn apply_block_to_state(
    state: &mut RuntimeState,
    block: SignedBlock,
) -> Result<Option<FinalizedRecords>> {
    let mut finalized_health_records = Vec::new();
    let mut finalized_browser_records = Vec::new();
    let mut finalized_compute_records = Vec::new();
    if state.seen_blocks.contains(&block.hash) || block.body.height <= state.chain.height {
        return Ok(None);
    }
    state.chain.apply_block(&block)?;
    for tx in &block.body.transactions {
        if matches!(tx.body.kind, TransactionKind::HealthCheck { .. })
            && let Some(record) = state.chain.finalized_health_checks.get(&tx.hash)
        {
            finalized_health_records.push(record.clone());
        }
        if matches!(tx.body.kind, TransactionKind::BrowserCheck { .. })
            && let Some(record) = state.chain.finalized_browser_checks.get(&tx.hash)
        {
            finalized_browser_records.push(record.clone());
        }
        if matches!(tx.body.kind, TransactionKind::ComputeJob { .. })
            && let Some(record) = state.chain.finalized_compute_jobs.get(&tx.hash)
        {
            finalized_compute_records.push(record.clone());
        }
    }
    state.seen_blocks.insert(block.hash.clone());
    for tx in &block.body.transactions {
        state.mempool.remove(&tx.hash);
        state.receipts.remove(&tx.hash);
        state.browser_receipts.remove(&tx.hash);
        state.compute_receipts.remove(&tx.hash);
    }
    for batch in &block.body.monitor_browser_batches {
        if let Ok(tx_hash) = monitor_browser_tx_hash(&batch.monitor_id, &batch.slot_key) {
            state.browser_receipts.remove(&tx_hash);
        }
    }
    for batch in &block.body.storage_proof_batches {
        if let Some(first) = batch.receipts.first() {
            let key = storage_proof_window_key(
                &first.body.contract_id,
                first.body.window_start,
                first.body.window_end,
            );
            state.storage_proof_receipts.remove(&key);
        }
    }
    for observation in &block.body.heartbeat_observations {
        let key = heartbeat_slot_key(&observation.body.monitor_id, &observation.body.slot_key);
        if let Some(items) = state.heartbeat_observations.get_mut(&key) {
            items.retain(|item| item.id != observation.id);
            if items.is_empty() {
                state.heartbeat_observations.remove(&key);
            }
        }
    }
    state.active_view = 0;
    state.view_started_at = Utc::now();
    prune_pending_state(state);
    Ok(Some((
        finalized_health_records,
        finalized_browser_records,
        finalized_compute_records,
    )))
}

fn apply_block_approval_to_state(
    state: &mut RuntimeState,
    approval: SignedBlockApproval,
) -> Result<bool> {
    if approval.body.chain_id != state.chain.chain_id {
        bail!("block approval is for a different chain");
    }
    if !state.chain.validators.contains(&approval.body.approver) {
        bail!("block approval signer is not a validator");
    }
    crate::wallet::verify_block_approval(&approval)?;
    let slot_key = block_approval_slot_key(
        approval.body.height,
        approval.body.view,
        &approval.body.previous_hash,
    );
    if let Some(existing) = state.block_approvals.get(&slot_key) {
        if existing.body.block_hash != approval.body.block_hash {
            bail!("validator already approved a different block for this height and view");
        }
        return Ok(false);
    }
    state.block_approvals.insert(slot_key, approval);
    Ok(true)
}

fn apply_view_advance_to_state(
    state: &mut RuntimeState,
    active_view: u64,
    view_started_at: DateTime<Utc>,
) {
    state.active_view = active_view;
    state.view_started_at = view_started_at;
    retain_current_block_approval_slot(state);
}

fn prune_pending_state(state: &mut RuntimeState) {
    let mut ordered: Vec<SignedTransaction> = state.mempool.values().cloned().collect();
    ordered.sort_by(|left, right| {
        left.body
            .created_at
            .cmp(&right.body.created_at)
            .then_with(|| left.body.nonce.cmp(&right.body.nonce))
            .then_with(|| left.hash.cmp(&right.hash))
    });

    let mut retained = BTreeMap::new();
    let mut seen_nonces = BTreeSet::new();
    for tx in ordered {
        if state.chain.is_finalized_health_check(&tx.hash) {
            continue;
        }
        if state.chain.validate_transaction_basic(&tx).is_err() {
            continue;
        }
        if !seen_nonces.insert((tx.signer.clone(), tx.body.nonce)) {
            continue;
        }
        retained.insert(tx.hash.clone(), tx);
    }

    let retained_hashes: BTreeSet<String> = retained.keys().cloned().collect();
    state.mempool = retained;
    state
        .receipts
        .retain(|tx_hash, _| retained_hashes.contains(tx_hash));
    state
        .compute_receipts
        .retain(|tx_hash, _| retained_hashes.contains(tx_hash));
    state.browser_receipts.retain(|tx_hash, receipts| {
        if retained_hashes.contains(tx_hash) {
            return true;
        }
        receipts
            .first()
            .and_then(|receipt| {
                let monitor_id = receipt.body.monitor_id.as_deref()?;
                let slot_key = receipt.body.slot_key.as_deref()?;
                let monitor = state.chain.monitors.get(monitor_id)?;
                if !monitor.spec.is_browser() {
                    return None;
                }
                let status = state
                    .chain
                    .monitor_slot_history
                    .get(monitor_id)
                    .and_then(|slots| slots.get(slot_key))
                    .map(|slot| slot.status.clone());
                Some(!matches!(
                    status,
                    Some(
                        MonitorSlotStatus::Ok
                            | MonitorSlotStatus::RecoveredLate
                            | MonitorSlotStatus::MissedUnconfirmed
                            | MonitorSlotStatus::MissedServiceReachable
                            | MonitorSlotStatus::DownConfirmed
                            | MonitorSlotStatus::InsufficientFunds
                    )
                ))
            })
            .unwrap_or(false)
    });
    state.storage_proof_receipts.retain(|_, receipts| {
        receipts
            .first()
            .and_then(|receipt| {
                let contract = state
                    .chain
                    .storage_contracts
                    .get(&receipt.body.contract_id)?;
                Some(
                    matches!(
                        contract.status,
                        crate::protocol::StorageContractStatus::Active
                    ) && receipt.body.window_start == contract.last_proven_at
                        && receipt.body.window_end <= Utc::now(),
                )
            })
            .unwrap_or(false)
    });
    state
        .heartbeat_observations
        .retain(|_, items| !items.is_empty());
    prune_client_nonces(state, Utc::now());
    state.seen_txs = state
        .chain
        .finalized_health_check_ids
        .iter()
        .cloned()
        .chain(state.chain.finalized_compute_job_ids.iter().cloned())
        .chain(state.mempool.keys().cloned())
        .collect();
    state.seen_receipts = state
        .receipts
        .values()
        .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
        .collect();
    state.seen_browser_receipts = state
        .browser_receipts
        .values()
        .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
        .collect();
    state.seen_compute_receipts = state
        .compute_receipts
        .values()
        .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
        .collect();
    state.seen_storage_proof_receipts = state
        .storage_proof_receipts
        .values()
        .flat_map(|receipts| receipts.iter().map(|receipt| receipt.id.clone()))
        .collect();
    state.seen_heartbeat_observations = state
        .heartbeat_observations
        .values()
        .flat_map(|items| items.iter().map(|item| item.id.clone()))
        .collect();
    if state.mempool.is_empty()
        && state.storage_proof_receipts.is_empty()
        && state.compute_receipts.is_empty()
    {
        state.active_view = 0;
        state.view_started_at = Utc::now();
    }
    retain_current_block_approval_slot(state);
}

fn block_approval_slot_key(height: u64, view: u64, previous_hash: &str) -> String {
    format!("{height}:{view}:{previous_hash}")
}

fn heartbeat_slot_key(monitor_id: &str, slot_key: &str) -> String {
    format!("{monitor_id}:{slot_key}")
}

fn storage_proof_window_key(
    contract_id: &str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> String {
    format!(
        "{}:{}:{}",
        contract_id,
        window_start.to_rfc3339(),
        window_end.to_rfc3339()
    )
}

fn normalize_route_host(host: &str) -> Result<String> {
    let host = host
        .trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains('\\') {
        bail!("domain route host is invalid");
    }
    Ok(host)
}

fn retain_current_block_approval_slot(state: &mut RuntimeState) {
    let current_slot = block_approval_slot_key(
        state.chain.height + 1,
        state.active_view,
        &state.chain.last_block_hash,
    );
    state
        .block_approvals
        .retain(|slot, _| slot == &current_slot);
}

fn default_view_started_at() -> DateTime<Utc> {
    Utc::now()
}

#[allow(clippy::too_many_arguments)]
fn candidate_block_fits_limits(
    chain_id: &str,
    height: u64,
    view: u64,
    previous_hash: &str,
    proposer: &str,
    transactions: &[SignedTransaction],
    health_batches: &[crate::protocol::BlockHealthBatch],
    browser_batches: &[BlockBrowserBatch],
    compute_batches: &[BlockComputeBatch],
    monitor_browser_batches: &[MonitorBrowserBatch],
    heartbeat_observations: &[SignedHeartbeatObservation],
    monitor_evaluations: &[MonitorEvaluation],
    confirmation_batches: &[MonitorConfirmationBatch],
    storage_proof_batches: &[StorageProofBatch],
) -> Result<bool> {
    let body = BlockBody {
        chain_id: chain_id.to_string(),
        height,
        view,
        previous_hash: previous_hash.to_string(),
        proposer: proposer.to_string(),
        proposed_at: Utc::now(),
        transactions: transactions.to_vec(),
        health_batches: health_batches.to_vec(),
        browser_batches: browser_batches.to_vec(),
        compute_batches: compute_batches.to_vec(),
        monitor_browser_batches: monitor_browser_batches.to_vec(),
        heartbeat_observations: heartbeat_observations.to_vec(),
        monitor_evaluations: monitor_evaluations.to_vec(),
        confirmation_batches: confirmation_batches.to_vec(),
        storage_proof_batches: storage_proof_batches.to_vec(),
    };
    Ok(validate_block_body_limits(&body).is_ok())
}

fn block_archive_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("blocks")
}

fn journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("state.wal")
}

fn block_archive_path(state_dir: &Path, height: u64) -> PathBuf {
    block_archive_dir(state_dir).join(format!("{height:020}.json"))
}

fn health_check_archive_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("health_checks")
}

fn health_check_archive_path(state_dir: &Path, tx_hash: &str) -> PathBuf {
    health_check_archive_dir(state_dir).join(format!("{tx_hash}.json"))
}

fn browser_check_archive_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("browser_checks")
}

fn browser_check_archive_path(state_dir: &Path, tx_hash: &str) -> PathBuf {
    browser_check_archive_dir(state_dir).join(format!("{tx_hash}.json"))
}

fn compute_job_archive_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("compute_jobs")
}

fn compute_job_archive_path(state_dir: &Path, tx_hash: &str) -> PathBuf {
    compute_job_archive_dir(state_dir).join(format!("{tx_hash}.json"))
}

fn compute_artifact_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("compute_artifacts")
}

fn compute_sandbox_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("compute_sandbox")
}

fn browser_artifact_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("browser_artifacts")
}

async fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    let temp_path = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(&temp_path, payload).await?;
    fs::rename(&temp_path, path).await?;
    Ok(())
}

async fn append_journal_event(state_dir: &Path, event: &PersistedJournalEvent) -> Result<()> {
    let path = journal_path(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_vec(event)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await?;
    file.write_all(&payload).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    Ok(())
}

async fn clear_journal_events(state_dir: &Path) -> Result<()> {
    fs::write(journal_path(state_dir), b"").await?;
    Ok(())
}

async fn load_journal_events(state_dir: &Path) -> Result<Vec<PersistedJournalEvent>> {
    let path = journal_path(state_dir);
    if !fs::try_exists(&path).await? {
        return Ok(Vec::new());
    }
    let payload = fs::read_to_string(path).await?;
    payload
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn read_json_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !fs::try_exists(path).await? {
        return Ok(None);
    }
    let payload = fs::read(path).await?;
    Ok(Some(serde_json::from_slice(&payload)?))
}

async fn archive_block(state_dir: &Path, block: &SignedBlock) -> Result<()> {
    write_json_atomic(&block_archive_path(state_dir, block.body.height), block).await
}

async fn load_archived_block(state_dir: &Path, height: u64) -> Result<Option<SignedBlock>> {
    read_json_optional(&block_archive_path(state_dir, height)).await
}

async fn archive_finalized_health_check(
    state_dir: &Path,
    record: &FinalizedHealthCheck,
) -> Result<()> {
    write_json_atomic(
        &health_check_archive_path(state_dir, &record.tx_hash),
        record,
    )
    .await
}

async fn load_archived_finalized_health_check(
    state_dir: &Path,
    tx_hash: &str,
) -> Result<Option<FinalizedHealthCheck>> {
    read_json_optional(&health_check_archive_path(state_dir, tx_hash)).await
}

async fn archive_finalized_browser_check(
    state_dir: &Path,
    record: &FinalizedBrowserCheck,
) -> Result<()> {
    write_json_atomic(
        &browser_check_archive_path(state_dir, &record.tx_hash),
        record,
    )
    .await
}

async fn load_archived_finalized_browser_check(
    state_dir: &Path,
    tx_hash: &str,
) -> Result<Option<FinalizedBrowserCheck>> {
    read_json_optional(&browser_check_archive_path(state_dir, tx_hash)).await
}

async fn archive_finalized_compute_job(
    state_dir: &Path,
    record: &FinalizedComputeJob,
) -> Result<()> {
    write_json_atomic(
        &compute_job_archive_path(state_dir, &record.tx_hash),
        record,
    )
    .await
}

async fn load_archived_finalized_compute_job(
    state_dir: &Path,
    tx_hash: &str,
) -> Result<Option<FinalizedComputeJob>> {
    read_json_optional(&compute_job_archive_path(state_dir, tx_hash)).await
}

async fn migrate_legacy_archives(
    state_dir: &Path,
    finalized_blocks: &BTreeMap<u64, SignedBlock>,
    finalized_health_checks: &BTreeMap<String, FinalizedHealthCheck>,
    finalized_browser_checks: &BTreeMap<String, FinalizedBrowserCheck>,
    finalized_compute_jobs: &BTreeMap<String, FinalizedComputeJob>,
) -> Result<()> {
    for (height, block) in finalized_blocks {
        let path = block_archive_path(state_dir, *height);
        if !fs::try_exists(&path).await? {
            write_json_atomic(&path, block).await?;
        }
    }
    for (tx_hash, record) in finalized_health_checks {
        let path = health_check_archive_path(state_dir, tx_hash);
        if !fs::try_exists(&path).await? {
            write_json_atomic(&path, record).await?;
        }
    }
    for (tx_hash, record) in finalized_browser_checks {
        let path = browser_check_archive_path(state_dir, tx_hash);
        if !fs::try_exists(&path).await? {
            write_json_atomic(&path, record).await?;
        }
    }
    for (tx_hash, record) in finalized_compute_jobs {
        let path = compute_job_archive_path(state_dir, tx_hash);
        if !fs::try_exists(&path).await? {
            write_json_atomic(&path, record).await?;
        }
    }
    Ok(())
}

async fn load_genesis(path: &Path) -> Result<crate::protocol::GenesisConfig> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read genesis {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

async fn load_state(
    path: PathBuf,
    genesis: &crate::protocol::GenesisConfig,
) -> Result<PersistedNodeState> {
    let chain = ChainState::from_genesis(genesis)?;
    if !fs::try_exists(&path).await? {
        return Ok(PersistedNodeState {
            chain,
            finalized_blocks: BTreeMap::new(),
            mempool: BTreeMap::new(),
            receipts: BTreeMap::new(),
            browser_receipts: BTreeMap::new(),
            compute_receipts: BTreeMap::new(),
            storage_proof_receipts: BTreeMap::new(),
            heartbeat_observations: BTreeMap::new(),
            heartbeat_client_nonces: BTreeMap::new(),
            block_approvals: BTreeMap::new(),
            delivered_alerts: BTreeMap::new(),
            active_view: 0,
            view_started_at: Utc::now(),
        });
    }

    let contents = fs::read_to_string(&path).await?;
    let mut persisted: PersistedNodeState = serde_json::from_str(&contents)?;
    if persisted.chain.chain_id != chain.chain_id {
        bail!("persisted state chain_id does not match the supplied genesis");
    }
    if persisted.chain.validators != chain.validators {
        bail!("persisted validator set does not match the supplied genesis");
    }
    if persisted.chain.treasury != chain.treasury {
        bail!("persisted treasury does not match the supplied genesis");
    }
    if persisted.chain.finalized_health_check_ids.is_empty()
        && !persisted.chain.finalized_health_checks.is_empty()
    {
        persisted.chain.finalized_health_check_ids = persisted
            .chain
            .finalized_health_checks
            .keys()
            .cloned()
            .collect();
    }
    if persisted.chain.finalized_browser_check_ids.is_empty()
        && !persisted.chain.finalized_browser_checks.is_empty()
    {
        persisted.chain.finalized_browser_check_ids = persisted
            .chain
            .finalized_browser_checks
            .keys()
            .cloned()
            .collect();
    }
    if persisted.chain.finalized_compute_job_ids.is_empty()
        && !persisted.chain.finalized_compute_jobs.is_empty()
    {
        persisted.chain.finalized_compute_job_ids = persisted
            .chain
            .finalized_compute_jobs
            .keys()
            .cloned()
            .collect();
    }
    if persisted.chain.block_history.is_empty() {
        persisted
            .chain
            .block_history
            .push(persisted.chain.last_block_hash.clone());
    }
    Ok(persisted)
}

type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, String)>;
type AcceptedApiResult<T> = std::result::Result<(StatusCode, Json<T>), (StatusCode, String)>;

async fn get_account(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(address): AxumPath<String>,
) -> ApiResult<AccountResponse> {
    Ok(Json(runtime.account_response(address).await))
}

async fn get_status(State(runtime): State<Arc<NodeRuntime>>) -> ApiResult<NodeStatusResponse> {
    Ok(Json(runtime.status_response().await))
}

async fn get_internal_block(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(height): AxumPath<u64>,
) -> ApiResult<SignedBlock> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let block = runtime
        .finalized_block_at_height(height)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("block {height} not found")))?;
    Ok(Json(block))
}

async fn get_ledger(State(runtime): State<Arc<NodeRuntime>>) -> ApiResult<LedgerSnapshot> {
    Ok(Json(runtime.ledger_snapshot().await))
}

async fn get_job(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(tx_hash): AxumPath<String>,
) -> ApiResult<JobResponse> {
    Ok(Json(runtime.job_response(tx_hash).await))
}

async fn get_swap_lock(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(quote_id): AxumPath<String>,
) -> ApiResult<SwapLockResponse> {
    Ok(Json(runtime.swap_lock_response(quote_id).await))
}

async fn get_storage_contract(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(contract_id): AxumPath<String>,
) -> ApiResult<StorageContractResponse> {
    Ok(Json(
        runtime
            .storage_contract_response(contract_id)
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_compute_artifact(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath((tx_hash, shard_id, path)): AxumPath<(String, String, String)>,
) -> std::result::Result<Response, (StatusCode, String)> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    let content_type = runtime
        .compute_artifact_content_type(&tx_hash, &shard_id, &path)
        .await
        .map_err(internal_error)?;
    let artifact_path = compute_artifact_path(
        &compute_artifact_dir(&runtime.config.state_dir),
        &tx_hash,
        &shard_id,
        &path,
    )
    .map_err(internal_error)?;
    let bytes = fs::read(&artifact_path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "compute artifact not found".to_string(),
        )
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    Ok((headers, Body::from(bytes)).into_response())
}

async fn get_domain_route(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(host): AxumPath<String>,
) -> ApiResult<DomainRouteResponse> {
    Ok(Json(
        runtime
            .domain_route_response(host)
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_adapters(State(runtime): State<Arc<NodeRuntime>>) -> ApiResult<AdaptersResponse> {
    Ok(Json(AdaptersResponse {
        adapters: runtime.swap_registry.adapter_ids(),
    }))
}

async fn submit_transaction(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn quote_swap(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(request): Json<SwapQuoteRequest>,
) -> ApiResult<SwapExecutionPlan> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    let plan = runtime
        .quote_and_plan(request)
        .await
        .map_err(internal_error)?;
    Ok(Json(plan))
}

async fn create_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match tx.body.kind {
        TransactionKind::MonitorCreate { .. } => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "monitor create endpoint requires a monitor_create transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn update_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorUpdate {
            monitor_id: tx_monitor_id,
            ..
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "monitor update endpoint requires a matching monitor_update transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn delete_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorDelete {
            monitor_id: tx_monitor_id,
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "monitor delete endpoint requires a matching monitor_delete transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn pause_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorPause {
            monitor_id: tx_monitor_id,
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "pause endpoint requires a matching monitor_pause transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn resume_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorResume {
            monitor_id: tx_monitor_id,
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "resume endpoint requires a matching monitor_resume transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn topup_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorTopUp {
            monitor_id: tx_monitor_id,
            ..
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "topup endpoint requires a matching monitor_top_up transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn rotate_monitor_token(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    AxumPath(monitor_id): AxumPath<String>,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_control_auth(&headers).map_err(auth_error)?;
    match &tx.body.kind {
        TransactionKind::MonitorUpdate {
            monitor_id: tx_monitor_id,
            ..
        } if tx_monitor_id == &monitor_id => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "rotate-token endpoint requires a matching monitor_update transaction".into(),
            ));
        }
    }
    let accepted = runtime
        .accept_transaction(tx.clone(), true)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn list_monitors(State(runtime): State<Arc<NodeRuntime>>) -> ApiResult<MonitorListResponse> {
    Ok(Json(runtime.list_monitors_response().await))
}

async fn get_monitor(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(monitor_id): AxumPath<String>,
) -> ApiResult<MonitorResponse> {
    Ok(Json(
        runtime
            .monitor_response(monitor_id)
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_monitor_slots(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(monitor_id): AxumPath<String>,
) -> ApiResult<MonitorSlotsResponse> {
    Ok(Json(
        runtime
            .monitor_slots_response(monitor_id)
            .await
            .map_err(internal_error)?,
    ))
}

async fn get_monitor_alerts(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(monitor_id): AxumPath<String>,
) -> ApiResult<MonitorAlertsResponse> {
    Ok(Json(
        runtime
            .monitor_alerts_response(monitor_id)
            .await
            .map_err(internal_error)?,
    ))
}

async fn ping_success_get(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(
        runtime,
        monitor_id,
        token,
        HeartbeatSignal::Success,
        Bytes::new(),
    )
    .await
}

async fn ping_success_post(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(runtime, monitor_id, token, HeartbeatSignal::Success, body).await
}

async fn ping_start_get(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(
        runtime,
        monitor_id,
        token,
        HeartbeatSignal::Start,
        Bytes::new(),
    )
    .await
}

async fn ping_start_post(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(runtime, monitor_id, token, HeartbeatSignal::Start, body).await
}

async fn ping_fail_get(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(
        runtime,
        monitor_id,
        token,
        HeartbeatSignal::Fail,
        Bytes::new(),
    )
    .await
}

async fn ping_fail_post(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath((monitor_id, token)): AxumPath<(String, String)>,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    accept_secret_ping(runtime, monitor_id, token, HeartbeatSignal::Fail, body).await
}

async fn ping_signed_post(
    State(runtime): State<Arc<NodeRuntime>>,
    AxumPath(monitor_id): AxumPath<String>,
    Query(query): Query<PingSignalQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    let signal = parse_heartbeat_signal(query.signal.as_deref(), &headers)?;
    accept_signed_ping(runtime, monitor_id, signal, headers, body).await
}

async fn gossip_transaction(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(tx): Json<SignedTransaction>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_transaction(tx.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: tx.hash,
    }))
}

async fn gossip_receipt(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(receipt): Json<SignedHealthReceipt>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_receipt(receipt.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: receipt.id,
    }))
}

async fn gossip_browser_receipt(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(receipt): Json<SignedBrowserReceipt>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_browser_receipt(receipt.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: receipt.id,
    }))
}

async fn gossip_compute_receipt(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(receipt): Json<SignedComputeReceipt>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_compute_receipt(receipt.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: receipt.id,
    }))
}

async fn gossip_storage_proof_receipt(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(receipt): Json<SignedStorageProofReceipt>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_storage_proof_receipt(receipt.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: receipt.id,
    }))
}

async fn gossip_heartbeat_observation(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(observation): Json<SignedHeartbeatObservation>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_heartbeat_observation(observation.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: observation.id,
    }))
}

async fn run_monitor_confirmation(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(request): Json<MonitorConfirmRequest>,
) -> ApiResult<MonitorConfirmationContribution> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let (chain_id, monitor) = {
        let state = runtime.state.read().await;
        let monitor = state
            .chain
            .monitors
            .get(&request.monitor_id)
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("unknown monitor {}", request.monitor_id),
                )
            })?;
        (state.chain.chain_id.clone(), monitor)
    };
    let contribution = runtime
        .execute_monitor_confirmation_contribution(
            &chain_id,
            &monitor,
            &request.slot_key,
            request.assigned_validator_count,
            request.direct_probe,
        )
        .await
        .map_err(internal_error)?;
    Ok(Json(contribution))
}

async fn gossip_block(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(block): Json<SignedBlock>,
) -> ApiResult<SubmittedResponse> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let accepted = runtime
        .accept_block(block.clone(), false)
        .await
        .map_err(internal_error)?;
    Ok(Json(SubmittedResponse {
        accepted,
        id: block.hash,
    }))
}

async fn approve_block(
    State(runtime): State<Arc<NodeRuntime>>,
    headers: HeaderMap,
    Json(block): Json<SignedBlock>,
) -> ApiResult<SignedBlockApproval> {
    runtime.require_gossip_auth(&headers).map_err(auth_error)?;
    let approval = runtime
        .approve_block_proposal(&block)
        .await
        .map_err(internal_error)?;
    Ok(Json(approval))
}

async fn accept_secret_ping(
    runtime: Arc<NodeRuntime>,
    monitor_id: String,
    token: String,
    signal: HeartbeatSignal,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    let response = runtime
        .record_secret_ping(monitor_id, token, signal, body)
        .await
        .map_err(internal_error)?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

async fn accept_signed_ping(
    runtime: Arc<NodeRuntime>,
    monitor_id: String,
    signal: HeartbeatSignal,
    headers: HeaderMap,
    body: Bytes,
) -> AcceptedApiResult<PingAcceptedResponse> {
    let response = runtime
        .record_signed_ping(monitor_id, signal, &headers, body)
        .await
        .map_err(internal_error)?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

fn internal_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

fn auth_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, error.to_string())
}

fn require_bearer_token(headers: &HeaderMap, expected: Option<&str>, scope: &str) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let supplied = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| anyhow::anyhow!("missing bearer token for {scope}"))?;
    if supplied != expected {
        bail!("invalid bearer token for {scope}");
    }
    Ok(())
}

fn bearer_token_value(token: &str) -> String {
    format!("Bearer {token}")
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, net::SocketAddr};

    use chrono::Duration as ChronoDuration;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        protocol::{GenesisConfig, HealthReceiptBody, SignedTransaction, TransactionBody},
        wallet::Wallet,
    };

    fn test_genesis(
        validators: &[Address],
        treasury: Address,
        requester: Address,
    ) -> GenesisConfig {
        GenesisConfig {
            chain_id: "testnet".into(),
            treasury,
            validators: validators.to_vec(),
            chain_started_at: Utc::now(),
            block_time_secs: 1,
            min_health_receipts: 2,
            airdrops: BTreeMap::from([(requester, 5)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        }
    }

    async fn runtime_for_validator(
        validator_wallet: &Wallet,
        validators: &[Wallet],
        requester: &Wallet,
    ) -> Result<(NodeRuntime, tempfile::TempDir, NodeConfig)> {
        let temp = tempdir()?;
        let wallet_path = temp.path().join("validator.json");
        validator_wallet.save_insecure_plaintext(&wallet_path)?;

        let genesis = test_genesis(
            &validators.iter().map(Wallet::address).collect::<Vec<_>>(),
            validators[0].address(),
            requester.address(),
        );
        let genesis_path = temp.path().join("genesis.json");
        fs::write(&genesis_path, serde_json::to_vec_pretty(&genesis)?)?;

        let config = NodeConfig {
            bind_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            wallet_path,
            genesis_path,
            state_dir: temp.path().join("state"),
            peers: Vec::new(),
            swap_config_path: None,
            notification_policies_path: None,
            probe_agents_path: None,
            browser_runner_program: None,
            browser_runner_args: Vec::new(),
            browser_cache_dir: None,
            browser_secret_store_path: None,
            control_api_token: None,
            gossip_api_token: None,
            wallet_passphrase: None,
        };
        let runtime = NodeRuntime::from_config(config.clone()).await?;

        Ok((runtime, temp, config))
    }

    #[tokio::test]
    async fn stale_view_rotates_approval_slot_and_allows_reapproval() {
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let validator_c = Wallet::generate();
        let requester = Wallet::generate();
        let validators = vec![
            validator_a.clone(),
            validator_b.clone(),
            validator_c.clone(),
        ];

        let (runtime, _temp, _config) =
            runtime_for_validator(&validator_b, &validators, &requester)
                .await
                .unwrap();

        let pending_tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::Transfer {
                        to: validator_a.address(),
                        amount: 1,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        runtime.accept_transaction(pending_tx, false).await.unwrap();

        let view_zero_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
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
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        runtime
            .approve_block_proposal(&view_zero_block)
            .await
            .unwrap();

        let competing_view_zero_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now() + ChronoDuration::seconds(1),
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: Vec::new(),
                    confirmation_batches: Vec::new(),
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        assert!(
            runtime
                .approve_block_proposal(&competing_view_zero_block)
                .await
                .is_err()
        );

        {
            let mut state = runtime.state.write().await;
            state.view_started_at = Utc::now() - ChronoDuration::seconds(2);
        }
        runtime.advance_view_if_stale().await.unwrap();

        {
            let state = runtime.state.read().await;
            assert_eq!(state.active_view, 1);
            assert_eq!(state.block_approvals.len(), 0);
            assert_eq!(
                state
                    .chain
                    .scheduled_proposer_for_view(1, state.active_view),
                &validator_b.address()
            );
        }

        let view_one_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 1,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
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
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let approval = runtime
            .approve_block_proposal(&view_one_block)
            .await
            .unwrap();
        assert_eq!(approval.body.view, 1);
        assert_eq!(approval.body.block_hash, view_one_block.hash);
    }

    #[tokio::test]
    async fn startup_replays_pending_journal_before_compacting() {
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let validator_c = Wallet::generate();
        let requester = Wallet::generate();
        let validators = vec![
            validator_a.clone(),
            validator_b.clone(),
            validator_c.clone(),
        ];

        let (runtime, _temp, config) = runtime_for_validator(&validator_b, &validators, &requester)
            .await
            .unwrap();

        let request_id = "restart-replay-request".to_string();
        let pending_tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::HealthCheck {
                        spec: crate::protocol::HealthCheckSpec {
                            request_id: request_id.clone(),
                            url: "https://example.com/health".into(),
                            method: crate::protocol::HealthHttpMethod::Get,
                            headers: BTreeMap::new(),
                            query: BTreeMap::new(),
                            timeout_ms: 1_000,
                            expected_status: Some(200),
                            assertions: Vec::new(),
                            body_json: None,
                            allow_insecure_http: false,
                            allow_private_targets: false,
                        },
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        runtime
            .accept_transaction(pending_tx.clone(), false)
            .await
            .unwrap();

        let receipt = validator_a
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: pending_tx.hash.clone(),
                    request_id: request_id.clone(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 42,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: Some("{\"ready\":true}".into()),
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        runtime.accept_receipt(receipt, false).await.unwrap();

        {
            let mut state = runtime.state.write().await;
            state.view_started_at = Utc::now() - ChronoDuration::seconds(2);
        }
        runtime.advance_view_if_stale().await.unwrap();

        let journal_before_restart =
            fs::read_to_string(journal_path(&config.state_dir)).expect("journal should exist");
        assert!(journal_before_restart.contains("transaction_accepted"));
        assert!(journal_before_restart.contains("receipt_accepted"));
        assert!(journal_before_restart.contains("view_advanced"));

        drop(runtime);

        let restarted = NodeRuntime::from_config(config.clone()).await.unwrap();
        let state = restarted.state.read().await;
        assert_eq!(state.chain.height, 0);
        assert_eq!(state.active_view, 1);
        assert!(state.mempool.contains_key(&pending_tx.hash));
        assert_eq!(state.receipts.get(&pending_tx.hash).map(Vec::len), Some(1));
        drop(state);

        let compacted_journal =
            fs::read_to_string(journal_path(&config.state_dir)).expect("journal should exist");
        assert!(compacted_journal.trim().is_empty());
    }
}
