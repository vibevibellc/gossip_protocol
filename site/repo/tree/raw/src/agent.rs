use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    browser::{
        BrowserRunnerConfig, DelegatedBrowserReceiptBody, SignedBrowserAgentLease,
        SignedDelegatedBrowserReceipt, execute_browser_check,
    },
    compute::{
        ComputeJobSpec, DelegatedComputeShardReceiptBody, SignedComputeShardLease,
        SignedDelegatedComputeShardReceipt, default_compute_replication,
    },
    compute_sandbox::{compute_artifact_path, execute_compute_shard_isolated},
    health::execute_health_check,
    protocol::{DelegatedProbeReceiptBody, SignedDelegatedProbeReceipt, SignedProbeAgentLease},
    wallet::{
        Wallet, verify_browser_agent_lease, verify_compute_shard_lease, verify_probe_agent_lease,
    },
};

#[derive(Debug, Clone)]
pub struct ProbeAgentConfig {
    pub bind_addr: SocketAddr,
    pub wallet_path: PathBuf,
    pub region: Option<String>,
    pub network: Option<String>,
    pub api_token: Option<String>,
    pub wallet_passphrase: Option<String>,
    pub browser_runner_program: Option<PathBuf>,
    pub browser_runner_args: Vec<String>,
    pub browser_cache_dir: Option<PathBuf>,
    pub browser_artifact_dir: Option<PathBuf>,
    pub browser_secret_store_path: Option<PathBuf>,
    pub compute_artifact_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfirmationResponse {
    pub delegated_receipt: SignedDelegatedProbeReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBrowserResponse {
    pub delegated_receipt: SignedDelegatedBrowserReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentComputeResponse {
    pub delegated_receipt: SignedDelegatedComputeShardReceipt,
}

#[derive(Clone)]
pub struct ProbeAgentRuntime {
    config: ProbeAgentConfig,
    wallet: Wallet,
}

impl ProbeAgentRuntime {
    pub fn from_config(config: ProbeAgentConfig) -> Result<Self> {
        let wallet = Wallet::from_file(&config.wallet_path, config.wallet_passphrase.as_deref())?;
        Ok(Self { config, wallet })
    }

    pub fn address(&self) -> String {
        self.wallet.address()
    }

    pub async fn run(self) -> Result<()> {
        let runtime = Arc::new(self);
        let app = Router::new()
            .route(
                "/v1/internal/agent/confirm",
                post(run_probe_agent_confirmation),
            )
            .route("/v1/internal/agent/browser", post(run_probe_agent_browser))
            .route(
                "/v1/internal/agent/compute-shard",
                post(run_probe_agent_compute_shard),
            )
            .route(
                "/v1/internal/agent/compute-artifacts/:tx_hash/:shard_id/*path",
                get(get_probe_agent_compute_artifact),
            )
            .with_state(runtime.clone());

        let listener = tokio::net::TcpListener::bind(runtime.config.bind_addr).await?;
        info!(
            address = %runtime.address(),
            bind = %runtime.config.bind_addr,
            region = ?runtime.config.region,
            network = ?runtime.config.network,
            "gossip_protocol probe agent listening"
        );
        axum::serve(listener, app).await?;
        Ok(())
    }

    fn require_api_auth(&self, headers: &HeaderMap) -> Result<()> {
        let Some(expected) = self.config.api_token.as_deref() else {
            return Ok(());
        };
        let supplied = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| anyhow!("missing bearer token for probe agent API"))?;
        if supplied != expected {
            bail!("invalid bearer token for probe agent API");
        }
        Ok(())
    }

    async fn execute_confirmation(
        &self,
        lease: SignedProbeAgentLease,
    ) -> Result<AgentConfirmationResponse> {
        verify_probe_agent_lease(&lease)?;
        if lease.body.agent_public_key != self.address() {
            bail!("probe agent lease is not addressed to this agent");
        }
        let now = Utc::now();
        if now > lease.body.expires_at {
            bail!("probe agent lease expired");
        }

        let outcome = execute_health_check(&lease.body.spec).await;
        let delegated_receipt =
            self.wallet
                .sign_delegated_probe_receipt(SignedDelegatedProbeReceipt {
                    id: String::new(),
                    body: DelegatedProbeReceiptBody {
                        chain_id: lease.body.chain_id.clone(),
                        monitor_id: lease.body.monitor_id.clone(),
                        slot_key: lease.body.slot_key.clone(),
                        agent_public_key: String::new(),
                        parent_validator: lease.body.parent_validator.clone(),
                        lease_id: Some(lease.id.clone()),
                        request_id: Some(lease.body.request_id.clone()),
                        region: self.config.region.clone(),
                        network: self.config.network.clone(),
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
                })?;
        Ok(AgentConfirmationResponse { delegated_receipt })
    }

    async fn execute_browser(
        &self,
        lease: SignedBrowserAgentLease,
    ) -> Result<AgentBrowserResponse> {
        verify_browser_agent_lease(&lease)?;
        if lease.body.agent_public_key != self.address() {
            bail!("browser agent lease is not addressed to this agent");
        }
        let now = Utc::now();
        if now > lease.body.expires_at {
            bail!("browser agent lease expired");
        }

        let execution = execute_browser_check(
            &lease.body.spec,
            &lease.body.tx_hash,
            &self.browser_runner_config(),
        )
        .await?;
        let delegated_receipt =
            self.wallet
                .sign_delegated_browser_receipt(SignedDelegatedBrowserReceipt {
                    id: String::new(),
                    body: DelegatedBrowserReceiptBody {
                        chain_id: lease.body.chain_id.clone(),
                        tx_hash: lease.body.tx_hash.clone(),
                        request_id: lease.body.request_id.clone(),
                        monitor_id: lease.body.monitor_id.clone(),
                        slot_key: lease.body.slot_key.clone(),
                        agent_public_key: String::new(),
                        parent_validator: lease.body.parent_validator.clone(),
                        lease_id: Some(lease.id.clone()),
                        region: self.config.region.clone(),
                        network: self.config.network.clone(),
                        observed_at: Utc::now(),
                        package_hash: crate::browser::browser_package_hash(
                            &lease.body.spec.package,
                        )?,
                        runtime_hash: crate::browser::browser_runtime_hash(
                            &lease.body.spec.package.runtime,
                        )?,
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
                })?;
        Ok(AgentBrowserResponse { delegated_receipt })
    }

    async fn execute_compute_shard(
        &self,
        lease: SignedComputeShardLease,
    ) -> Result<AgentComputeResponse> {
        verify_compute_shard_lease(&lease)?;
        if lease.body.agent_public_key != self.address() {
            bail!("compute shard lease is not addressed to this agent");
        }
        let now = Utc::now();
        if now > lease.body.expires_at {
            bail!("compute shard lease expired");
        }

        let spec = ComputeJobSpec {
            request_id: lease.body.request_id.clone(),
            workload: lease.body.workload.clone(),
            shards: vec![lease.body.shard.clone()],
            reducer: lease.body.reducer.clone(),
            max_runtime_secs: lease.body.max_runtime_secs,
            replication: default_compute_replication(),
            sandbox: lease.body.sandbox.clone(),
            artifact_policy: lease.body.artifact_policy.clone(),
        };
        let output = execute_compute_shard_isolated(
            &spec,
            &lease.body.shard,
            &lease.body.tx_hash,
            &self.address(),
            &self.compute_sandbox_dir(),
            &self.compute_artifact_dir(),
        )
        .await?;
        let delegated_receipt = self.wallet.sign_delegated_compute_shard_receipt(
            SignedDelegatedComputeShardReceipt {
                id: String::new(),
                body: DelegatedComputeShardReceiptBody {
                    chain_id: lease.body.chain_id.clone(),
                    tx_hash: lease.body.tx_hash.clone(),
                    request_id: lease.body.request_id.clone(),
                    agent_public_key: String::new(),
                    parent_validator: lease.body.parent_validator.clone(),
                    lease_id: lease.id.clone(),
                    job_hash: lease.body.job_hash.clone(),
                    shard_output: output,
                    observed_at: Utc::now(),
                },
                signature: String::new(),
            },
        )?;
        Ok(AgentComputeResponse { delegated_receipt })
    }

    fn browser_runner_config(&self) -> BrowserRunnerConfig {
        let base = std::env::temp_dir().join(format!("gossip-protocol-agent-{}", self.address()));
        BrowserRunnerConfig {
            program: self.config.browser_runner_program.clone(),
            args: self.config.browser_runner_args.clone(),
            cache_dir: self
                .config
                .browser_cache_dir
                .clone()
                .unwrap_or_else(|| base.join("browser_cache")),
            artifact_root: self
                .config
                .browser_artifact_dir
                .clone()
                .unwrap_or_else(|| base.join("browser_artifacts")),
            secret_store_path: self.config.browser_secret_store_path.clone(),
        }
    }

    fn compute_artifact_dir(&self) -> PathBuf {
        self.config.compute_artifact_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir()
                .join(format!("gossip-protocol-agent-{}", self.address()))
                .join("compute_artifacts")
        })
    }

    fn compute_sandbox_dir(&self) -> PathBuf {
        self.compute_artifact_dir()
            .parent()
            .map(|parent| parent.join("compute_sandbox"))
            .unwrap_or_else(|| {
                std::env::temp_dir()
                    .join(format!("gossip-protocol-agent-{}", self.address()))
                    .join("compute_sandbox")
            })
    }
}

type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, String)>;

async fn run_probe_agent_confirmation(
    State(runtime): State<Arc<ProbeAgentRuntime>>,
    headers: HeaderMap,
    Json(lease): Json<SignedProbeAgentLease>,
) -> ApiResult<AgentConfirmationResponse> {
    runtime.require_api_auth(&headers).map_err(auth_error)?;
    let response = runtime
        .execute_confirmation(lease)
        .await
        .map_err(internal_error)?;
    Ok(Json(response))
}

async fn run_probe_agent_browser(
    State(runtime): State<Arc<ProbeAgentRuntime>>,
    headers: HeaderMap,
    Json(lease): Json<SignedBrowserAgentLease>,
) -> ApiResult<AgentBrowserResponse> {
    runtime.require_api_auth(&headers).map_err(auth_error)?;
    let response = runtime
        .execute_browser(lease)
        .await
        .map_err(internal_error)?;
    Ok(Json(response))
}

async fn run_probe_agent_compute_shard(
    State(runtime): State<Arc<ProbeAgentRuntime>>,
    headers: HeaderMap,
    Json(lease): Json<SignedComputeShardLease>,
) -> ApiResult<AgentComputeResponse> {
    runtime.require_api_auth(&headers).map_err(auth_error)?;
    let response = runtime
        .execute_compute_shard(lease)
        .await
        .map_err(internal_error)?;
    Ok(Json(response))
}

async fn get_probe_agent_compute_artifact(
    State(runtime): State<Arc<ProbeAgentRuntime>>,
    headers: HeaderMap,
    AxumPath((tx_hash, shard_id, path)): AxumPath<(String, String, String)>,
) -> std::result::Result<Response, (StatusCode, String)> {
    runtime.require_api_auth(&headers).map_err(auth_error)?;
    let artifact_path =
        compute_artifact_path(&runtime.compute_artifact_dir(), &tx_hash, &shard_id, &path)
            .map_err(internal_error)?;
    let bytes = tokio::fs::read(&artifact_path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "compute artifact not found".to_string(),
        )
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((headers, Body::from(bytes)).into_response())
}

fn internal_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}

fn auth_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        browser::{
            BrowserArtifactPolicy, BrowserCheckSpec, BrowserEngine, BrowserJourneyPackage,
            BrowserJourneySpec, BrowserRuntimeProfile, SessionCachePolicy, SignedBrowserAgentLease,
        },
        protocol::{HealthCheckSpec, HealthHttpMethod, ProbeAgentLeaseBody},
    };
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn agent_rejects_leases_for_other_agents() {
        let wallet = Wallet::generate();
        let validator = Wallet::generate();
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("agent.json");
        wallet.save_insecure_plaintext(&wallet_path).unwrap();
        let runtime = ProbeAgentRuntime::from_config(ProbeAgentConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            wallet_path,
            region: Some("us-west".into()),
            network: Some("testnet".into()),
            api_token: None,
            wallet_passphrase: None,
            browser_runner_program: None,
            browser_runner_args: Vec::new(),
            browser_cache_dir: None,
            browser_artifact_dir: None,
            browser_secret_store_path: None,
            compute_artifact_dir: None,
        })
        .unwrap();

        let lease = validator
            .sign_probe_agent_lease(crate::protocol::SignedProbeAgentLease {
                id: String::new(),
                body: ProbeAgentLeaseBody {
                    chain_id: "testnet".into(),
                    lease_id: "lease-1".into(),
                    parent_validator: String::new(),
                    agent_public_key: Wallet::generate().address(),
                    monitor_id: "m".into(),
                    slot_key: Utc::now().to_rfc3339(),
                    request_id: "r".into(),
                    spec: HealthCheckSpec {
                        request_id: "r".into(),
                        url: "https://example.com/health".into(),
                        method: HealthHttpMethod::Get,
                        headers: BTreeMap::new(),
                        query: BTreeMap::new(),
                        timeout_ms: 1_000,
                        expected_status: Some(200),
                        assertions: Vec::new(),
                        body_json: None,
                        allow_insecure_http: false,
                        allow_private_targets: false,
                    },
                    issued_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::seconds(5),
                    audit: false,
                },
                signature: String::new(),
            })
            .unwrap();

        assert!(runtime.execute_confirmation(lease).await.is_err());
    }

    #[tokio::test]
    async fn agent_rejects_browser_leases_for_other_agents() {
        let wallet = Wallet::generate();
        let validator = Wallet::generate();
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("agent.json");
        wallet.save_insecure_plaintext(&wallet_path).unwrap();
        let runtime = ProbeAgentRuntime::from_config(ProbeAgentConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            wallet_path,
            region: Some("us-west".into()),
            network: Some("testnet".into()),
            api_token: None,
            wallet_passphrase: None,
            browser_runner_program: None,
            browser_runner_args: Vec::new(),
            browser_cache_dir: None,
            browser_artifact_dir: None,
            browser_secret_store_path: None,
            compute_artifact_dir: None,
        })
        .unwrap();

        let lease = validator
            .sign_browser_agent_lease(SignedBrowserAgentLease {
                id: String::new(),
                body: crate::browser::BrowserAgentLeaseBody {
                    chain_id: "testnet".into(),
                    lease_id: "lease-1".into(),
                    parent_validator: String::new(),
                    agent_public_key: Wallet::generate().address(),
                    tx_hash: "tx-1".into(),
                    request_id: "browser-1".into(),
                    monitor_id: None,
                    slot_key: None,
                    spec: BrowserCheckSpec {
                        request_id: "browser-1".into(),
                        package: BrowserJourneyPackage {
                            package_id: "pkg".into(),
                            owner: validator.address(),
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
                                cache_mode: Default::default(),
                            },
                            journey: BrowserJourneySpec {
                                journey_id: "smoke".into(),
                                entry_url: "https://example.com".into(),
                                steps: vec![crate::browser::BrowserStep::Navigate {
                                    url: "https://example.com".into(),
                                }],
                                max_runtime_secs: 5,
                                per_step_timeout_ms: 1_000,
                            },
                            artifact_policy: BrowserArtifactPolicy {
                                capture_video: false,
                                capture_trace: false,
                                capture_screenshot_on_failure: true,
                            },
                            session_cache: SessionCachePolicy {
                                enabled: false,
                                namespace: None,
                                max_age_secs: 0,
                            },
                            approved_at: Utc::now(),
                            approved_by: validator.address(),
                            tags: BTreeMap::new(),
                        },
                    },
                    issued_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::seconds(5),
                    audit: false,
                },
                signature: String::new(),
            })
            .unwrap();

        assert!(runtime.execute_browser(lease).await.is_err());
    }
}
