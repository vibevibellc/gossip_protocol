use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    agent::{ProbeAgentConfig, ProbeAgentRuntime},
    browser::{
        BrowserCheckSpec, BrowserJourneyPackage, browser_package_hash, browser_runtime_hash,
        validate_browser_journey_package,
    },
    compute::{
        ComputeJobSpec, ComputeModuleRef, validate_compute_job_spec, validate_compute_module_ref,
    },
    ledger::ChainState,
    node::{NodeConfig, NodeRuntime},
    protocol::{
        DEFAULT_STORAGE_CHUNK_SIZE_BYTES, DEFAULT_STORAGE_PROOF_INTERVAL_SECS,
        DEFAULT_STORAGE_PROOF_SAMPLE_COUNT, DNS_LEASE_COST_PER_SUBDOMAIN_SECOND, GenesisConfig,
        HealthCheckSpec, HealthHttpMethod, MonitorSpec, ResponseAssertion,
        STORAGE_REWARD_PER_QUANTUM_SECOND, SettlementAsset, SignedStorageProofReceipt,
        SignedSwapQuote, SignedTransaction, StorageContractRecord, StorageContractSpec,
        StorageMode, StorageProofReceiptBody, SwapExecutionPlan, SwapQuoteRequest, SwapSide,
        TransactionBody, TransactionKind, default_min_health_receipts, default_swap_quote_ttl_secs,
        hash_secret_token, new_request_id, parse_amount, storage_challenge_seed,
    },
    storage::{
        StorageBundleBuildOptions, StorageBundleManifest, StorageBundleMode, StorageHostConfig,
        build_storage_bundle, fetch_storage_proof_samples, run_storage_host,
    },
    wallet::{Wallet, WalletFile},
};

#[derive(Parser)]
#[command(
    name = "gossip_protocol",
    about = "Decentralized health-check token protocol"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    Genesis {
        #[command(subcommand)]
        command: GenesisCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Tx {
        #[command(subcommand)]
        command: TxCommand,
    },
    Swap {
        #[command(subcommand)]
        command: SwapCommand,
    },
    Monitor {
        #[command(subcommand)]
        command: MonitorCommand,
    },
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    Create(WalletCreateArgs),
    Address { wallet: PathBuf },
    Show { wallet: PathBuf },
}

#[derive(Args)]
struct WalletCreateArgs {
    out: PathBuf,
    #[arg(long)]
    passphrase_env: Option<String>,
    #[arg(long)]
    insecure_plaintext: bool,
}

#[derive(Subcommand)]
enum GenesisCommand {
    Create(GenesisCreateArgs),
}

#[derive(Args)]
struct GenesisCreateArgs {
    #[arg(long)]
    out: PathBuf,
    #[arg(long, required = true)]
    validator_wallet: Vec<PathBuf>,
    #[arg(long)]
    treasury: Option<String>,
    #[arg(long)]
    airdrop: Vec<String>,
    #[arg(long)]
    storage_airdrop: Vec<String>,
    #[arg(long)]
    compute_airdrop: Vec<String>,
    #[arg(long)]
    dns_airdrop: Vec<String>,
    #[arg(long, default_value = "10")]
    block_time_secs: u64,
    #[arg(long)]
    min_receipts: Option<usize>,
    #[arg(long)]
    chain_id: Option<String>,
}

#[derive(Subcommand)]
enum NodeCommand {
    Run(NodeRunArgs),
}

#[derive(Args)]
struct NodeRunArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:9000")]
    bind: SocketAddr,
    #[arg(long)]
    peer: Vec<String>,
    #[arg(long)]
    swap_config: Option<PathBuf>,
    #[arg(long)]
    notification_policies: Option<PathBuf>,
    #[arg(long)]
    probe_agents: Option<PathBuf>,
    #[arg(long)]
    browser_runner_program: Option<PathBuf>,
    #[arg(long)]
    browser_runner_arg: Vec<String>,
    #[arg(long)]
    browser_cache_dir: Option<PathBuf>,
    #[arg(long)]
    browser_secret_store: Option<PathBuf>,
    #[arg(long)]
    control_api_token: Option<String>,
    #[arg(long)]
    gossip_api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Subcommand)]
enum TxCommand {
    Transfer(TransferArgs),
    StorageTransfer(TransferArgs),
    ComputeTransfer(TransferArgs),
    DnsTransfer(TransferArgs),
    HealthCheck(HealthCheckArgs),
    BrowserCheck(BrowserCheckArgs),
    ComputeJob(ComputeJobArgs),
    MonitorCreate(MonitorCreateArgs),
    MonitorUpdate(MonitorUpdateArgs),
    MonitorPause(MonitorActionArgs),
    MonitorResume(MonitorActionArgs),
    MonitorTopUp(MonitorTopUpArgs),
    MonitorDelete(MonitorActionArgs),
    MonitorRotateToken(MonitorUpdateArgs),
    StorageCreate(StorageCreateArgs),
    StorageTopUp(StorageTopUpArgs),
    StorageCancel(StorageCancelArgs),
    DomainOfferingCreate(DomainOfferingCreateArgs),
    DomainOfferingPause(DomainOfferingActionArgs),
    DomainOfferingResume(DomainOfferingActionArgs),
    DomainOfferingRetire(DomainOfferingActionArgs),
    DomainLeaseCreate(DomainLeaseCreateArgs),
    DomainLeaseRenew(DomainLeaseRenewArgs),
    DomainLeaseBind(DomainLeaseBindArgs),
    DomainLeaseCancel(DomainLeaseActionArgs),
}

#[derive(Args)]
struct TransferArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    to: String,
    #[arg(long)]
    amount: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct HealthCheckArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    url: String,
    #[arg(long, value_enum, default_value = "get")]
    method: MethodArg,
    #[arg(long)]
    header: Vec<String>,
    #[arg(long)]
    query: Vec<String>,
    #[arg(long, default_value = "3000")]
    timeout_ms: u64,
    #[arg(long, default_value = "200")]
    expect_status: u16,
    #[arg(long)]
    assert_json: Vec<String>,
    #[arg(long)]
    assert_json_exists: Vec<String>,
    #[arg(long)]
    assert_header: Vec<String>,
    #[arg(long)]
    assert_body_contains: Vec<String>,
    #[arg(long)]
    body_json: Option<String>,
    #[arg(long)]
    allow_http: bool,
    #[arg(long)]
    allow_private_targets: bool,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct BrowserCheckArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    package_file: PathBuf,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct ComputeJobArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    spec_file: PathBuf,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct MonitorCreateArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    spec_file: PathBuf,
    #[arg(long)]
    initial_budget: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct MonitorUpdateArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    monitor_id: String,
    #[arg(long)]
    spec_file: PathBuf,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct MonitorActionArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    monitor_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct MonitorTopUpArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    monitor_id: String,
    #[arg(long)]
    amount: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct StorageCreateArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    spec_file: PathBuf,
    #[arg(long)]
    prepaid_balance: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct StorageTopUpArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    contract_id: String,
    #[arg(long)]
    amount: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct StorageCancelArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    contract_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainOfferingCreateArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    suffix: String,
    #[arg(long)]
    gateway_url: String,
    #[arg(long)]
    offering_id: Option<String>,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainOfferingActionArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    offering_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainLeaseCreateArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    offering_id: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    target_contract_id: String,
    #[arg(long)]
    duration_secs: u64,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainLeaseRenewArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    lease_id: String,
    #[arg(long)]
    duration_secs: u64,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainLeaseBindArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    lease_id: String,
    #[arg(long)]
    target_contract_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct DomainLeaseActionArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    lease_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Subcommand)]
enum SwapCommand {
    Quote(SwapQuoteArgs),
    Lock(SwapLockArgs),
    Cancel(SwapCancelArgs),
    Settle(SwapSettleArgs),
}

#[derive(Subcommand)]
enum MonitorCommand {
    HashToken { token: String },
}

#[derive(Subcommand)]
enum BrowserCommand {
    ValidatePackage { package_file: PathBuf },
    HashPackage { package_file: PathBuf },
}

#[derive(Subcommand)]
enum StorageCommand {
    Bundle(StorageBundleArgs),
    ModuleRef(StorageModuleRefArgs),
    Host(StorageHostArgs),
    Prove(StorageProveArgs),
}

#[derive(Args)]
struct StorageBundleArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long)]
    host: String,
    #[arg(long)]
    contract_id: Option<String>,
    #[arg(long, value_enum, default_value = "encrypted")]
    mode: StorageBundleModeArg,
    #[arg(long)]
    index_path: Option<String>,
    #[arg(long, default_value_t = DEFAULT_STORAGE_CHUNK_SIZE_BYTES)]
    chunk_size_bytes: u64,
    #[arg(long, default_value = "2592000")]
    duration_secs: u64,
    #[arg(long, default_value_t = DEFAULT_STORAGE_PROOF_INTERVAL_SECS)]
    proof_interval_secs: u64,
    #[arg(long, default_value_t = DEFAULT_STORAGE_PROOF_SAMPLE_COUNT)]
    proof_sample_count: u16,
    #[arg(long, default_value_t = STORAGE_REWARD_PER_QUANTUM_SECOND)]
    reward_rate_per_64mib_second: u64,
}

#[derive(Args)]
struct StorageModuleRefArgs {
    #[arg(long)]
    manifest_file: PathBuf,
    #[arg(long)]
    host_url: String,
    #[arg(long)]
    path: String,
}

#[derive(Args)]
struct StorageHostArgs {
    #[arg(long)]
    store_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:9100")]
    bind: SocketAddr,
    #[arg(long)]
    node: Option<String>,
}

#[derive(Args)]
struct StorageProveArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    host_url: String,
    #[arg(long)]
    contract_id: String,
    #[arg(long)]
    window_end: Option<String>,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Subcommand)]
enum AgentCommand {
    Run(AgentRunArgs),
}

#[derive(Args)]
struct AgentRunArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
    #[arg(long)]
    browser_runner_program: Option<PathBuf>,
    #[arg(long)]
    browser_runner_arg: Vec<String>,
    #[arg(long)]
    browser_cache_dir: Option<PathBuf>,
    #[arg(long)]
    browser_artifact_dir: Option<PathBuf>,
    #[arg(long)]
    browser_secret_store: Option<PathBuf>,
    #[arg(long)]
    compute_artifact_dir: Option<PathBuf>,
}

#[derive(Args)]
struct SwapQuoteArgs {
    #[arg(long)]
    node: String,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    amount: String,
    #[arg(long, value_enum)]
    side: SwapSideArg,
    #[arg(long, value_enum)]
    asset: SettlementAssetArg,
    #[arg(long)]
    adapter: Option<String>,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long, default_value_t = default_swap_quote_ttl_secs())]
    ttl_secs: u64,
}

#[derive(Args)]
struct SwapLockArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    quote_file: PathBuf,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct SwapCancelArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    quote_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Args)]
struct SwapSettleArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    quote_id: String,
    #[arg(long)]
    api_token: Option<String>,
    #[arg(long)]
    wallet_passphrase_env: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum MethodArg {
    Get,
    Head,
    Post,
}

#[derive(Clone, Copy, ValueEnum)]
enum SwapSideArg {
    Buy,
    Sell,
}

#[derive(Clone, Copy, ValueEnum)]
enum SettlementAssetArg {
    Usdc,
    Usdt,
}

#[derive(Clone, Copy, ValueEnum)]
enum StorageBundleModeArg {
    Encrypted,
    PublicRaw,
}

impl From<StorageBundleModeArg> for StorageBundleMode {
    fn from(value: StorageBundleModeArg) -> Self {
        match value {
            StorageBundleModeArg::Encrypted => StorageBundleMode::Encrypted,
            StorageBundleModeArg::PublicRaw => StorageBundleMode::PublicRaw,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct NodeStatusCliResponse {
    chain_id: String,
    last_block_hash: String,
}

#[derive(Debug, Deserialize)]
struct StorageContractCliResponse {
    contract: StorageContractRecord,
}

#[derive(Debug, Serialize)]
struct StorageBundleCliOutput {
    spec: StorageContractSpec,
    contract_dir: String,
    manifest_path: String,
    spec_path: String,
    secrets_path: Option<String>,
}

pub async fn run() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Commands::Wallet { command } => wallet_command(command),
        Commands::Genesis { command } => genesis_command(command).await,
        Commands::Node { command } => node_command(command).await,
        Commands::Tx { command } => tx_command(command).await,
        Commands::Swap { command } => swap_command(command).await,
        Commands::Monitor { command } => monitor_command(command),
        Commands::Browser { command } => browser_command(command).await,
        Commands::Storage { command } => storage_command(command).await,
        Commands::Agent { command } => agent_command(command).await,
    }
}

fn init_tracing() {
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,reqwest=warn")),
        )
        .with_target(false)
        .try_init();
}

fn wallet_command(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Create(args) => {
            let wallet = Wallet::generate();
            let file = if args.insecure_plaintext {
                if args.passphrase_env.is_some() {
                    bail!("--insecure-plaintext cannot be combined with --passphrase-env");
                }
                wallet.save_insecure_plaintext(&args.out)?;
                wallet.to_file_insecure_plaintext()
            } else {
                let passphrase = read_required_passphrase(args.passphrase_env.as_deref())?;
                wallet.save_encrypted(&args.out, &passphrase)?;
                wallet.to_file_encrypted(&passphrase)?
            };
            println!("{}", serde_json::to_string_pretty(&file)?);
            Ok(())
        }
        WalletCommand::Address { wallet } => {
            let wallet = read_wallet_file(&wallet)?;
            println!("{}", wallet.address);
            Ok(())
        }
        WalletCommand::Show { wallet } => {
            let contents = std::fs::read_to_string(&wallet)
                .with_context(|| format!("failed to read wallet {}", wallet.display()))?;
            let file: WalletFile = serde_json::from_str(&contents)?;
            println!("{}", serde_json::to_string_pretty(&file)?);
            Ok(())
        }
    }
}

async fn genesis_command(command: GenesisCommand) -> Result<()> {
    match command {
        GenesisCommand::Create(args) => create_genesis(args).await,
    }
}

async fn create_genesis(args: GenesisCreateArgs) -> Result<()> {
    let validators = args
        .validator_wallet
        .iter()
        .map(|path| read_wallet_file(path.as_path()))
        .collect::<Result<Vec<_>>>()?;
    let validator_addresses = validators
        .iter()
        .map(|wallet| wallet.address.clone())
        .collect::<Vec<_>>();
    if validator_addresses.is_empty() {
        bail!("at least one validator wallet is required");
    }

    let treasury = args
        .treasury
        .unwrap_or_else(|| validator_addresses[0].clone());
    let airdrops = parse_airdrops(&args.airdrop)?;
    let storage_airdrops = parse_airdrops(&args.storage_airdrop)?;
    let compute_airdrops = parse_airdrops(&args.compute_airdrop)?;
    let dns_airdrops = parse_airdrops(&args.dns_airdrop)?;
    let min_health_receipts =
        resolve_min_health_receipts(args.min_receipts, validator_addresses.len())?;

    let genesis = GenesisConfig {
        chain_id: args
            .chain_id
            .unwrap_or_else(|| format!("gossip-protocol-{}", new_request_id())),
        treasury,
        validators: validator_addresses,
        chain_started_at: Utc::now(),
        block_time_secs: args.block_time_secs,
        min_health_receipts,
        airdrops,
        storage_airdrops,
        compute_airdrops,
        dns_airdrops,
    };
    ChainState::from_genesis(&genesis).context("refusing to write invalid genesis")?;

    let payload = serde_json::to_vec_pretty(&genesis)?;
    tokio::fs::write(&args.out, payload).await?;
    println!("{}", serde_json::to_string_pretty(&genesis)?);
    Ok(())
}

async fn node_command(command: NodeCommand) -> Result<()> {
    match command {
        NodeCommand::Run(args) => {
            let runtime = NodeRuntime::from_config(NodeConfig {
                bind_addr: args.bind,
                wallet_path: args.wallet,
                genesis_path: args.genesis,
                state_dir: args.state_dir,
                peers: args.peer,
                swap_config_path: args.swap_config,
                notification_policies_path: args.notification_policies,
                probe_agents_path: args.probe_agents,
                browser_runner_program: args.browser_runner_program,
                browser_runner_args: args.browser_runner_arg,
                browser_cache_dir: args.browser_cache_dir,
                browser_secret_store_path: args.browser_secret_store,
                control_api_token: args.control_api_token,
                gossip_api_token: args.gossip_api_token,
                wallet_passphrase: read_optional_passphrase(args.wallet_passphrase_env.as_deref())?,
            })
            .await?;
            runtime.run().await
        }
    }
}

async fn tx_command(command: TxCommand) -> Result<()> {
    match command {
        TxCommand::Transfer(args) => submit_transfer(args).await,
        TxCommand::StorageTransfer(args) => submit_storage_transfer(args).await,
        TxCommand::ComputeTransfer(args) => submit_compute_transfer(args).await,
        TxCommand::DnsTransfer(args) => submit_dns_transfer(args).await,
        TxCommand::HealthCheck(args) => submit_health_check(args).await,
        TxCommand::BrowserCheck(args) => submit_browser_check(args).await,
        TxCommand::ComputeJob(args) => submit_compute_job(args).await,
        TxCommand::MonitorCreate(args) => submit_monitor_create(args).await,
        TxCommand::MonitorUpdate(args) => submit_monitor_update(args, false).await,
        TxCommand::MonitorPause(args) => submit_monitor_pause(args).await,
        TxCommand::MonitorResume(args) => submit_monitor_resume(args).await,
        TxCommand::MonitorTopUp(args) => submit_monitor_topup(args).await,
        TxCommand::MonitorDelete(args) => submit_monitor_delete(args).await,
        TxCommand::MonitorRotateToken(args) => submit_monitor_update(args, true).await,
        TxCommand::StorageCreate(args) => submit_storage_create(args).await,
        TxCommand::StorageTopUp(args) => submit_storage_topup(args).await,
        TxCommand::StorageCancel(args) => submit_storage_cancel(args).await,
        TxCommand::DomainOfferingCreate(args) => submit_domain_offering_create(args).await,
        TxCommand::DomainOfferingPause(args) => submit_domain_offering_action(args, "pause").await,
        TxCommand::DomainOfferingResume(args) => {
            submit_domain_offering_action(args, "resume").await
        }
        TxCommand::DomainOfferingRetire(args) => {
            submit_domain_offering_action(args, "retire").await
        }
        TxCommand::DomainLeaseCreate(args) => submit_domain_lease_create(args).await,
        TxCommand::DomainLeaseRenew(args) => submit_domain_lease_renew(args).await,
        TxCommand::DomainLeaseBind(args) => submit_domain_lease_bind(args).await,
        TxCommand::DomainLeaseCancel(args) => submit_domain_lease_cancel(args).await,
    }
}

async fn submit_transfer(args: TransferArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::Transfer {
                to: args.to,
                amount,
            },
        },
        signature: String::new(),
    })?;

    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_storage_transfer(args: TransferArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::StorageTransfer {
                to: args.to,
                amount,
            },
        },
        signature: String::new(),
    })?;

    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_compute_transfer(args: TransferArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::ComputeTransfer {
                to: args.to,
                amount,
            },
        },
        signature: String::new(),
    })?;

    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_dns_transfer(args: TransferArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DnsTransfer {
                to: args.to,
                amount,
            },
        },
        signature: String::new(),
    })?;

    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_health_check(args: HealthCheckArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let headers = parse_name_value_pairs(&args.header, ':')?;
    let query = parse_name_value_pairs(&args.query, '=')?;
    let mut assertions = Vec::new();
    for path in args.assert_json_exists {
        assertions.push(ResponseAssertion::JsonFieldExists { path });
    }
    for input in args.assert_json {
        let (path, raw_value) = split_once(&input, '=')?;
        assertions.push(ResponseAssertion::JsonFieldEquals {
            path,
            value: parse_json_like_value(&raw_value),
        });
    }
    for input in args.assert_header {
        let (name, value) = split_once(&input, '=')?;
        assertions.push(ResponseAssertion::HeaderEquals { name, value });
    }
    for text in args.assert_body_contains {
        assertions.push(ResponseAssertion::BodyContains { text });
    }

    let body_json = if let Some(value) = args.body_json {
        Some(serde_json::from_str(&value).context("failed to parse --body-json")?)
    } else {
        None
    };

    let spec = HealthCheckSpec {
        request_id: new_request_id(),
        url: args.url,
        method: match args.method {
            MethodArg::Get => HealthHttpMethod::Get,
            MethodArg::Head => HealthHttpMethod::Head,
            MethodArg::Post => HealthHttpMethod::Post,
        },
        headers,
        query,
        timeout_ms: args.timeout_ms,
        expected_status: Some(args.expect_status),
        assertions,
        body_json,
        allow_insecure_http: args.allow_http,
        allow_private_targets: args.allow_private_targets,
    };

    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::HealthCheck { spec },
        },
        signature: String::new(),
    })?;

    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_browser_check(args: BrowserCheckArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let package = read_browser_package(&args.package_file)?;
    let spec = BrowserCheckSpec {
        request_id: new_request_id(),
        package,
    };
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::BrowserCheck { spec },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_compute_job(args: ComputeJobArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let spec = read_compute_job_spec(&args.spec_file)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::ComputeJob { spec },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_create(args: MonitorCreateArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let spec = read_monitor_spec(&args.spec_file)?;
    let initial_budget = parse_amount(&args.initial_budget)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorCreate {
                spec,
                initial_budget,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction_to_path(
        &args.node,
        args.api_token.as_deref(),
        "/v1/control/monitors",
        &tx,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_update(args: MonitorUpdateArgs, rotate_token: bool) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let spec = read_monitor_spec(&args.spec_file)?;
    if spec.monitor_id != args.monitor_id {
        bail!("monitor spec monitor_id must match --monitor-id");
    }
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorUpdate {
                monitor_id: args.monitor_id.clone(),
                spec,
            },
        },
        signature: String::new(),
    })?;
    let path = if rotate_token {
        format!("/v1/control/monitors/{}/rotate-token", args.monitor_id)
    } else {
        format!("/v1/control/monitors/{}", args.monitor_id)
    };
    submit_signed_transaction_to_path(&args.node, args.api_token.as_deref(), &path, &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_pause(args: MonitorActionArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorPause {
                monitor_id: args.monitor_id.clone(),
            },
        },
        signature: String::new(),
    })?;
    let path = format!("/v1/control/monitors/{}/pause", args.monitor_id);
    submit_signed_transaction_to_path(&args.node, args.api_token.as_deref(), &path, &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_resume(args: MonitorActionArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorResume {
                monitor_id: args.monitor_id.clone(),
            },
        },
        signature: String::new(),
    })?;
    let path = format!("/v1/control/monitors/{}/resume", args.monitor_id);
    submit_signed_transaction_to_path(&args.node, args.api_token.as_deref(), &path, &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_topup(args: MonitorTopUpArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorTopUp {
                monitor_id: args.monitor_id.clone(),
                amount,
            },
        },
        signature: String::new(),
    })?;
    let path = format!("/v1/control/monitors/{}/topup", args.monitor_id);
    submit_signed_transaction_to_path(&args.node, args.api_token.as_deref(), &path, &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_monitor_delete(args: MonitorActionArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::MonitorDelete {
                monitor_id: args.monitor_id.clone(),
            },
        },
        signature: String::new(),
    })?;
    let path = format!("/v1/control/monitors/{}", args.monitor_id);
    submit_signed_transaction_to_delete_path(&args.node, args.api_token.as_deref(), &path, &tx)
        .await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_storage_create(args: StorageCreateArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let spec = read_storage_contract_spec(&args.spec_file)?;
    let prepaid_balance = parse_amount(&args.prepaid_balance)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::StorageCreate {
                spec,
                prepaid_balance,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_storage_topup(args: StorageTopUpArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let amount = parse_amount(&args.amount)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::StorageTopUp {
                contract_id: args.contract_id,
                amount,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_storage_cancel(args: StorageCancelArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::StorageCancel {
                contract_id: args.contract_id,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_domain_offering_create(args: DomainOfferingCreateArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DomainOfferingCreate {
                offering_id: args.offering_id.unwrap_or_else(new_request_id),
                suffix: args.suffix,
                gateway_url: args.gateway_url,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_domain_offering_action(args: DomainOfferingActionArgs, action: &str) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let kind = match action {
        "pause" => TransactionKind::DomainOfferingPause {
            offering_id: args.offering_id,
        },
        "resume" => TransactionKind::DomainOfferingResume {
            offering_id: args.offering_id,
        },
        "retire" => TransactionKind::DomainOfferingRetire {
            offering_id: args.offering_id,
        },
        _ => bail!("unsupported domain offering action"),
    };
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind,
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_domain_lease_create(args: DomainLeaseCreateArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let cost = args
        .duration_secs
        .checked_mul(DNS_LEASE_COST_PER_SUBDOMAIN_SECOND)
        .ok_or_else(|| anyhow::anyhow!("domain lease cost overflow"))?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DomainLeaseCreate {
                offering_id: args.offering_id,
                label: args.label,
                target_contract_id: args.target_contract_id,
                duration_secs: args.duration_secs,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    let payload = serde_json::json!({
        "dns_cost": crate::protocol::format_amount(cost),
        "transaction": tx,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

async fn submit_domain_lease_renew(args: DomainLeaseRenewArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let cost = args
        .duration_secs
        .checked_mul(DNS_LEASE_COST_PER_SUBDOMAIN_SECOND)
        .ok_or_else(|| anyhow::anyhow!("domain lease cost overflow"))?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DomainLeaseRenew {
                lease_id: args.lease_id,
                duration_secs: args.duration_secs,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    let payload = serde_json::json!({
        "dns_cost": crate::protocol::format_amount(cost),
        "transaction": tx,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

async fn submit_domain_lease_bind(args: DomainLeaseBindArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DomainLeaseBind {
                lease_id: args.lease_id,
                target_contract_id: args.target_contract_id,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_domain_lease_cancel(args: DomainLeaseActionArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::DomainLeaseCancel {
                lease_id: args.lease_id,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn swap_command(command: SwapCommand) -> Result<()> {
    match command {
        SwapCommand::Quote(args) => {
            let client = reqwest::Client::new();
            let request = SwapQuoteRequest {
                wallet: args.wallet,
                token_amount: parse_amount(&args.amount)?,
                side: match args.side {
                    SwapSideArg::Buy => SwapSide::Buy,
                    SwapSideArg::Sell => SwapSide::Sell,
                },
                settlement_asset: match args.asset {
                    SettlementAssetArg::Usdc => SettlementAsset::Usdc,
                    SettlementAssetArg::Usdt => SettlementAsset::Usdt,
                },
                adapter: args.adapter,
                ttl_secs: args.ttl_secs,
            };
            let url = format!("{}/v1/control/swap/quote", args.node.trim_end_matches('/'));
            let mut call = client.post(url);
            if let Some(token) = args.api_token.as_deref() {
                call = call.header("authorization", format!("Bearer {token}"));
            }
            let response = call.json(&request).send().await?.error_for_status()?;
            let payload: Value = response.json().await?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SwapCommand::Lock(args) => submit_swap_lock(args).await,
        SwapCommand::Cancel(args) => submit_swap_cancel(args).await,
        SwapCommand::Settle(args) => submit_swap_settle(args).await,
    }
}

fn monitor_command(command: MonitorCommand) -> Result<()> {
    match command {
        MonitorCommand::HashToken { token } => {
            println!("{}", hash_secret_token(&token)?);
            Ok(())
        }
    }
}

async fn browser_command(command: BrowserCommand) -> Result<()> {
    match command {
        BrowserCommand::ValidatePackage { package_file } => {
            let package = read_browser_package(&package_file)?;
            validate_browser_journey_package(&package)?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            Ok(())
        }
        BrowserCommand::HashPackage { package_file } => {
            let package = read_browser_package(&package_file)?;
            let payload = serde_json::json!({
                "package_hash": browser_package_hash(&package)?,
                "runtime_hash": browser_runtime_hash(&package.runtime)?,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
    }
}

async fn storage_command(command: StorageCommand) -> Result<()> {
    match command {
        StorageCommand::Bundle(args) => storage_bundle_command(args).await,
        StorageCommand::ModuleRef(args) => storage_module_ref_command(args).await,
        StorageCommand::Host(args) => {
            run_storage_host(StorageHostConfig {
                bind_addr: args.bind,
                store_dir: args.store_dir,
                node_url: args.node,
            })
            .await
        }
        StorageCommand::Prove(args) => storage_prove_command(args).await,
    }
}

async fn storage_bundle_command(args: StorageBundleArgs) -> Result<()> {
    let options = StorageBundleBuildOptions {
        contract_id: args.contract_id.unwrap_or_else(new_request_id),
        host: args.host,
        mode: args.mode.into(),
        chunk_size_bytes: args.chunk_size_bytes,
        duration_secs: args.duration_secs,
        proof_interval_secs: args.proof_interval_secs,
        proof_sample_count: args.proof_sample_count,
        reward_rate_per_64mib_second: args.reward_rate_per_64mib_second,
        index_path: args.index_path,
    };
    let build = build_storage_bundle(&args.input, &args.out_dir, options).await?;
    let output = StorageBundleCliOutput {
        spec: build.spec,
        contract_dir: build.contract_dir.display().to_string(),
        manifest_path: build.manifest_path.display().to_string(),
        spec_path: build.spec_path.display().to_string(),
        secrets_path: build.secrets_path.map(|path| path.display().to_string()),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn storage_module_ref_command(args: StorageModuleRefArgs) -> Result<()> {
    let manifest = read_storage_bundle_manifest(&args.manifest_file)?;
    if !matches!(manifest.mode, StorageMode::PublicRaw { .. }) {
        bail!("compute module refs require a public_raw storage bundle");
    }
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == args.path)
        .ok_or_else(|| anyhow::anyhow!("module path is missing from storage manifest"))?;
    let module_ref = ComputeModuleRef {
        contract_id: manifest.contract_id.clone(),
        host_url: args.host_url,
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        size_bytes: file.size_bytes,
        merkle_root: manifest.merkle_root.clone(),
    };
    validate_compute_module_ref(&module_ref)?;
    println!("{}", serde_json::to_string_pretty(&module_ref)?);
    Ok(())
}

async fn storage_prove_command(args: StorageProveArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let status = fetch_node_status(&args.node).await?;
    let contract = fetch_storage_contract(&args.node, &args.contract_id).await?;
    let window_end = resolve_storage_window_end(args.window_end.as_deref(), &contract)?;
    let challenge_seed = storage_challenge_seed(
        &status.chain_id,
        &contract.contract_id,
        &status.last_block_hash,
        contract.last_proven_at,
        window_end,
        &contract.spec.merkle_root,
    )?;
    let samples =
        fetch_storage_proof_samples(&args.host_url, &contract.spec, &challenge_seed).await?;
    let receipt = wallet.sign_storage_proof_receipt(SignedStorageProofReceipt {
        id: String::new(),
        body: StorageProofReceiptBody {
            chain_id: status.chain_id,
            contract_id: contract.contract_id.clone(),
            host: contract.host.clone(),
            validator: String::new(),
            window_start: contract.last_proven_at,
            window_end,
            observed_at: Utc::now(),
            bytes_stored: contract.spec.size_bytes,
            merkle_root: contract.spec.merkle_root.clone(),
            challenge_seed,
            samples,
            success: true,
            error: None,
        },
        signature: String::new(),
    })?;
    post_json_to_path(
        &args.node,
        args.api_token.as_deref(),
        "/v1/internal/storage-proof",
        &receipt,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

async fn agent_command(command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::Run(args) => {
            let runtime = ProbeAgentRuntime::from_config(ProbeAgentConfig {
                bind_addr: args.bind,
                wallet_path: args.wallet,
                region: args.region,
                network: args.network,
                api_token: args.api_token,
                wallet_passphrase: read_optional_passphrase(args.wallet_passphrase_env.as_deref())?,
                browser_runner_program: args.browser_runner_program,
                browser_runner_args: args.browser_runner_arg,
                browser_cache_dir: args.browser_cache_dir,
                browser_artifact_dir: args.browser_artifact_dir,
                browser_secret_store_path: args.browser_secret_store,
                compute_artifact_dir: args.compute_artifact_dir,
            })?;
            runtime.run().await
        }
    }
}

async fn submit_swap_lock(args: SwapLockArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let quote = read_signed_swap_quote(&args.quote_file)?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::SwapLock { quote },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_swap_cancel(args: SwapCancelArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::SwapCancel {
                quote_id: args.quote_id,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn submit_swap_settle(args: SwapSettleArgs) -> Result<()> {
    let wallet = load_signing_wallet(&args.wallet, args.wallet_passphrase_env.as_deref())?;
    let nonce = fetch_next_nonce(&args.node, &wallet.address()).await?;
    let tx = wallet.sign_transaction(SignedTransaction {
        hash: String::new(),
        signer: String::new(),
        body: TransactionBody {
            chain_id: fetch_chain_id(&args.node).await?,
            nonce,
            created_at: Utc::now(),
            kind: TransactionKind::SwapSettle {
                quote_id: args.quote_id,
            },
        },
        signature: String::new(),
    })?;
    submit_signed_transaction(&args.node, args.api_token.as_deref(), &tx).await?;
    println!("{}", serde_json::to_string_pretty(&tx)?);
    Ok(())
}

async fn fetch_next_nonce(node: &str, address: &str) -> Result<u64> {
    let response = reqwest::get(format!(
        "{}/v1/control/account/{}",
        node.trim_end_matches('/'),
        address
    ))
    .await?
    .error_for_status()?;
    let account: AccountResponse = response.json().await?;
    Ok(account.nonce + 1)
}

async fn fetch_chain_id(node: &str) -> Result<String> {
    let response = reqwest::get(format!("{}/v1/control/ledger", node.trim_end_matches('/')))
        .await?
        .error_for_status()?;
    let payload: Value = response.json().await?;
    payload
        .get("chain_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("node ledger response is missing chain_id"))
}

async fn fetch_node_status(node: &str) -> Result<NodeStatusCliResponse> {
    let response = reqwest::get(format!("{}/v1/control/status", node.trim_end_matches('/')))
        .await?
        .error_for_status()?;
    Ok(response.json().await?)
}

async fn fetch_storage_contract(node: &str, contract_id: &str) -> Result<StorageContractRecord> {
    let response = reqwest::get(format!(
        "{}/v1/control/storage/{}",
        node.trim_end_matches('/'),
        contract_id
    ))
    .await?
    .error_for_status()?;
    let payload: StorageContractCliResponse = response.json().await?;
    Ok(payload.contract)
}

fn resolve_storage_window_end(
    configured: Option<&str>,
    contract: &StorageContractRecord,
) -> Result<DateTime<Utc>> {
    let window_end = if let Some(value) = configured {
        DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("failed to parse --window-end {value}"))?
            .with_timezone(&Utc)
    } else {
        let mut end = Utc::now();
        let max_interval_end =
            contract.last_proven_at + Duration::seconds(contract.spec.proof_interval_secs as i64);
        if end > max_interval_end {
            end = max_interval_end;
        }
        if end > contract.expires_at {
            end = contract.expires_at;
        }
        end
    };

    if window_end <= contract.last_proven_at {
        bail!("storage proof window_end must be after the contract last_proven_at");
    }
    if window_end > Utc::now() {
        bail!("storage proof window_end cannot be in the future");
    }
    if window_end > contract.expires_at {
        bail!("storage proof window_end cannot exceed contract expiry");
    }
    let elapsed = window_end
        .signed_duration_since(contract.last_proven_at)
        .num_seconds();
    if elapsed <= 0 || elapsed as u64 > contract.spec.proof_interval_secs {
        bail!("storage proof window exceeds the contract proof interval");
    }
    Ok(window_end)
}

async fn submit_signed_transaction(
    node: &str,
    api_token: Option<&str>,
    tx: &SignedTransaction,
) -> Result<()> {
    submit_signed_transaction_to_path(node, api_token, "/v1/control/submit", tx).await
}

async fn submit_signed_transaction_to_path(
    node: &str,
    api_token: Option<&str>,
    path: &str,
    tx: &SignedTransaction,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", node.trim_end_matches('/'), path);
    let mut call = client.post(url);
    if let Some(token) = api_token {
        call = call.header("authorization", format!("Bearer {token}"));
    }
    let response = call.json(tx).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("node rejected transaction with status {status}: {body}");
    }
    Ok(())
}

async fn post_json_to_path<T: Serialize + ?Sized>(
    node: &str,
    api_token: Option<&str>,
    path: &str,
    payload: &T,
) -> Result<Value> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", node.trim_end_matches('/'), path);
    let mut call = client.post(url);
    if let Some(token) = api_token {
        call = call.header("authorization", format!("Bearer {token}"));
    }
    let response = call.json(payload).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("node rejected request with status {status}: {body}");
    }
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&body)?)
}

async fn submit_signed_transaction_to_delete_path(
    node: &str,
    api_token: Option<&str>,
    path: &str,
    tx: &SignedTransaction,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}{}", node.trim_end_matches('/'), path);
    let mut call = client.delete(url);
    if let Some(token) = api_token {
        call = call.header("authorization", format!("Bearer {token}"));
    }
    let response = call.json(tx).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("node rejected transaction with status {status}: {body}");
    }
    Ok(())
}

fn read_wallet_file(path: &Path) -> Result<WalletFile> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read wallet {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

fn load_signing_wallet(path: &Path, passphrase_env: Option<&str>) -> Result<Wallet> {
    let passphrase = read_optional_passphrase(passphrase_env)?;
    Wallet::from_file(path, passphrase.as_deref())
}

fn read_optional_passphrase(passphrase_env: Option<&str>) -> Result<Option<String>> {
    match passphrase_env {
        Some(env_name) => {
            Ok(Some(std::env::var(env_name).with_context(|| {
                format!("missing environment variable {env_name}")
            })?))
        }
        None => Ok(None),
    }
}

fn read_required_passphrase(passphrase_env: Option<&str>) -> Result<String> {
    let env_name = passphrase_env.ok_or_else(|| {
        anyhow::anyhow!(
            "wallet encryption requires --passphrase-env or an explicit --insecure-plaintext override"
        )
    })?;
    std::env::var(env_name).with_context(|| format!("missing environment variable {env_name}"))
}

fn read_signed_swap_quote(path: &Path) -> Result<SignedSwapQuote> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read swap quote {}", path.display()))?;
    if let Ok(plan) = serde_json::from_str::<SwapExecutionPlan>(&contents) {
        return Ok(plan.quote);
    }
    Ok(serde_json::from_str(&contents)?)
}

fn read_browser_package(path: &Path) -> Result<BrowserJourneyPackage> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read browser package {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_compute_job_spec(path: &Path) -> Result<ComputeJobSpec> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read compute job spec {}", path.display()))?;
    let spec: ComputeJobSpec = serde_json::from_str(&contents)?;
    validate_compute_job_spec(&spec)?;
    Ok(spec)
}

fn read_monitor_spec(path: &Path) -> Result<MonitorSpec> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read monitor spec {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_storage_contract_spec(path: &Path) -> Result<StorageContractSpec> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read storage contract spec {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_storage_bundle_manifest(path: &Path) -> Result<StorageBundleManifest> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read storage bundle manifest {}", path.display()))?;
    Ok(serde_json::from_str(&contents)?)
}

fn parse_airdrops(items: &[String]) -> Result<BTreeMap<String, u64>> {
    let mut out = BTreeMap::new();
    for item in items {
        let (address, amount) = split_once(item, '=')?;
        out.insert(address, parse_amount(&amount)?);
    }
    Ok(out)
}

fn parse_name_value_pairs(items: &[String], separator: char) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for item in items {
        let (key, value) = split_once(item, separator)?;
        out.insert(key, value);
    }
    Ok(out)
}

fn parse_json_like_value(input: &str) -> Value {
    serde_json::from_str(input).unwrap_or_else(|_| Value::String(input.to_string()))
}

fn split_once(input: &str, separator: char) -> Result<(String, String)> {
    let (left, right) = input
        .split_once(separator)
        .ok_or_else(|| anyhow::anyhow!("expected KEY{separator}VALUE format"))?;
    if left.is_empty() || right.is_empty() {
        bail!("expected KEY{separator}VALUE format");
    }
    Ok((left.to_string(), right.to_string()))
}

fn resolve_min_health_receipts(configured: Option<usize>, validator_count: usize) -> Result<usize> {
    if validator_count == 0 {
        bail!("at least one validator wallet is required");
    }
    match configured {
        Some(0) => bail!("--min-receipts must be at least 1"),
        Some(value) if value > validator_count => {
            bail!("--min-receipts cannot exceed the validator count ({validator_count})")
        }
        Some(value) => Ok(value),
        None => Ok(default_min_health_receipts().min(validator_count)),
    }
}

#[allow(dead_code)]
fn _validate_node_url(url: &str) -> Result<Url> {
    Ok(Url::parse(url)?)
}

#[cfg(test)]
mod tests {
    use super::resolve_min_health_receipts;

    #[test]
    fn default_receipt_threshold_scales_down_for_single_validator_bootstrap() {
        assert_eq!(resolve_min_health_receipts(None, 1).unwrap(), 1);
        assert_eq!(resolve_min_health_receipts(None, 3).unwrap(), 2);
    }

    #[test]
    fn explicit_receipt_threshold_must_fit_validator_count() {
        assert_eq!(resolve_min_health_receipts(Some(1), 1).unwrap(), 1);
        assert!(resolve_min_health_receipts(Some(0), 1).is_err());
        assert!(resolve_min_health_receipts(Some(2), 1).is_err());
    }
}
