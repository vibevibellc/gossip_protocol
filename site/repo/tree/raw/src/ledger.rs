use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    browser::{
        BlockBrowserBatch, BrowserOutcomeClass, SignedBrowserReceipt, browser_check_cost,
        validate_browser_check_spec,
    },
    compute::{
        BlockComputeBatch, ComputeJobSpec, SignedComputeReceipt, compute_job_cost_for_replication,
        compute_job_hash, compute_wasi_module_ref, reduce_compute_outputs,
        validate_compute_job_spec, validate_compute_output, validate_compute_output_artifacts,
    },
    protocol::{
        AccountSnapshot, Address, AlertFact, BlockBody, BlockHash, BlockHealthBatch,
        DNS_LEASE_COST_PER_SUBDOMAIN_SECOND, DomainIsolationMode, DomainLeaseRecord,
        DomainLeaseStatus, DomainOfferingRecord, DomainOfferingStatus, GenesisConfig,
        HeartbeatAuth, HeartbeatAuthMode, HeartbeatSignal, LedgerSnapshot,
        MONITOR_ALERT_DELIVERY_FEE, MONITOR_PING_INGRESS_FEE, MONITOR_SLOT_RESERVATION_FEE,
        MonitorBrowserBatch, MonitorConfirmationBatch, MonitorEvaluation, MonitorEvaluationKind,
        MonitorRecord, MonitorSlotRecord, MonitorSlotStatus, MonitorStatus, SignalPolicy,
        SignedBlock, SignedBlockApproval, SignedHealthReceipt, SignedHeartbeatObservation,
        SignedStorageProofReceipt, SignedSwapQuote, SignedTransaction, StorageContractRecord,
        StorageContractStatus, StorageMode, StorageProofBatch, TransactionKind, TxHash,
        canonical_heartbeat_client_message, compute_hash, confirmation_probe_cost,
        default_block_time_secs, default_min_health_receipts, dns_lease_cost, domain_fqdn,
        health_check_cost, monitor_browser_request_id, monitor_browser_slot_cost,
        monitor_browser_tx_hash, monitor_minimum_slot_balance, required_delegated_probe_receipts,
        required_monitor_confirmation_receipts, schedule_current_slot_start,
        schedule_next_slot_start, slot_deadline, storage_challenge_indices, storage_challenge_seed,
        storage_chunk_count, storage_reward_for_elapsed, validate_block_body_limits,
        validate_domain_label, validate_domain_offering_input, validate_health_check_spec,
        validate_monitor_spec, validate_storage_contract_spec, validate_storage_proof_sample,
    },
    wallet::{
        verify_block, verify_block_approval, verify_browser_receipt, verify_compute_receipt,
        verify_delegated_probe_receipt, verify_heartbeat_observation, verify_receipt,
        verify_signed_message, verify_storage_proof_receipt, verify_swap_quote, verify_transaction,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountState {
    pub balance: u64,
    pub storage_balance: u64,
    #[serde(default)]
    pub compute_balance: u64,
    pub dns_balance: u64,
    pub nonce: u64,
    pub locked_balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedHealthCheck {
    pub tx_hash: TxHash,
    pub requester: Address,
    pub finalized_at: DateTime<Utc>,
    pub receipts: Vec<SignedHealthReceipt>,
    #[serde(default)]
    pub rewarded_receipts: Vec<SignedHealthReceipt>,
    pub consensus_success: bool,
    pub success_count: usize,
    pub failure_count: usize,
    pub divergent_count: usize,
    pub requester_cost: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedBrowserCheck {
    pub tx_hash: TxHash,
    pub requester: Address,
    pub finalized_at: DateTime<Utc>,
    pub receipts: Vec<SignedBrowserReceipt>,
    #[serde(default)]
    pub rewarded_receipts: Vec<SignedBrowserReceipt>,
    pub consensus_success: bool,
    pub success_count: usize,
    pub failure_count: usize,
    pub divergent_count: usize,
    pub requester_cost: u64,
    pub package_hash: String,
    pub runtime_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedComputeJob {
    pub tx_hash: TxHash,
    pub requester: Address,
    pub finalized_at: DateTime<Utc>,
    pub receipts: Vec<SignedComputeReceipt>,
    #[serde(default)]
    pub rewarded_receipts: Vec<SignedComputeReceipt>,
    pub consensus_success: bool,
    pub success_count: usize,
    pub failure_count: usize,
    pub divergent_count: usize,
    pub requester_cost: u64,
    pub job_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduced_output: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSwapLock {
    pub quote: SignedSwapQuote,
    pub owner: Address,
    pub locked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub chain_id: String,
    pub treasury: Address,
    pub validators: Vec<Address>,
    pub chain_started_at: DateTime<Utc>,
    pub block_time_secs: u64,
    pub min_health_receipts: usize,
    pub height: u64,
    pub last_block_hash: BlockHash,
    pub accounts: BTreeMap<Address, AccountState>,
    #[serde(skip_serializing, default)]
    pub finalized_health_checks: BTreeMap<TxHash, FinalizedHealthCheck>,
    #[serde(default)]
    pub finalized_health_check_ids: BTreeSet<TxHash>,
    #[serde(skip_serializing, default)]
    pub finalized_browser_checks: BTreeMap<TxHash, FinalizedBrowserCheck>,
    #[serde(default)]
    pub finalized_browser_check_ids: BTreeSet<TxHash>,
    #[serde(skip_serializing, default)]
    pub finalized_compute_jobs: BTreeMap<TxHash, FinalizedComputeJob>,
    #[serde(default)]
    pub finalized_compute_job_ids: BTreeSet<TxHash>,
    #[serde(default)]
    pub pending_swap_locks: BTreeMap<String, PendingSwapLock>,
    #[serde(default)]
    pub monitors: BTreeMap<String, MonitorRecord>,
    #[serde(default)]
    pub monitor_slot_history: BTreeMap<String, BTreeMap<String, MonitorSlotRecord>>,
    #[serde(default)]
    pub alert_facts: BTreeMap<String, AlertFact>,
    #[serde(default)]
    pub storage_contracts: BTreeMap<String, StorageContractRecord>,
    #[serde(default)]
    pub domain_offerings: BTreeMap<String, DomainOfferingRecord>,
    #[serde(default)]
    pub domain_leases: BTreeMap<String, DomainLeaseRecord>,
    #[serde(skip_serializing, default)]
    pub block_history: Vec<BlockHash>,
}

impl ChainState {
    pub fn from_genesis(genesis: &GenesisConfig) -> Result<Self> {
        if genesis.validators.is_empty() {
            bail!("genesis must define at least one validator");
        }
        if genesis.min_health_receipts == 0 {
            bail!("min_health_receipts must be at least 1");
        }

        let mut validators = Vec::new();
        let mut seen = BTreeSet::new();
        for validator in &genesis.validators {
            if seen.insert(validator.clone()) {
                validators.push(validator.clone());
            }
        }

        if !seen.contains(&genesis.treasury) {
            bail!("treasury address must be part of the validator set");
        }
        if genesis.min_health_receipts > validators.len() {
            bail!("min_health_receipts cannot exceed the validator set size");
        }

        let mut accounts: BTreeMap<Address, AccountState> = BTreeMap::new();
        for validator in &validators {
            accounts.entry(validator.clone()).or_default();
        }
        for (address, amount) in &genesis.airdrops {
            accounts.entry(address.clone()).or_default().balance += amount;
        }
        for (address, amount) in &genesis.storage_airdrops {
            accounts.entry(address.clone()).or_default().storage_balance += amount;
        }
        for (address, amount) in &genesis.compute_airdrops {
            accounts.entry(address.clone()).or_default().compute_balance += amount;
        }
        for (address, amount) in &genesis.dns_airdrops {
            accounts.entry(address.clone()).or_default().dns_balance += amount;
        }

        Ok(Self {
            chain_id: genesis.chain_id.clone(),
            treasury: genesis.treasury.clone(),
            validators,
            chain_started_at: genesis.chain_started_at,
            block_time_secs: if genesis.block_time_secs == 0 {
                default_block_time_secs()
            } else {
                genesis.block_time_secs
            },
            min_health_receipts: if genesis.min_health_receipts == 0 {
                default_min_health_receipts()
            } else {
                genesis.min_health_receipts
            },
            height: 0,
            last_block_hash: "genesis".into(),
            accounts,
            finalized_health_checks: BTreeMap::new(),
            finalized_health_check_ids: BTreeSet::new(),
            finalized_browser_checks: BTreeMap::new(),
            finalized_browser_check_ids: BTreeSet::new(),
            finalized_compute_jobs: BTreeMap::new(),
            finalized_compute_job_ids: BTreeSet::new(),
            pending_swap_locks: BTreeMap::new(),
            monitors: BTreeMap::new(),
            monitor_slot_history: BTreeMap::new(),
            alert_facts: BTreeMap::new(),
            storage_contracts: BTreeMap::new(),
            domain_offerings: BTreeMap::new(),
            domain_leases: BTreeMap::new(),
            block_history: vec!["genesis".into()],
        })
    }

    pub fn account(&self, address: &str) -> AccountState {
        self.accounts.get(address).cloned().unwrap_or_default()
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        let accounts = self
            .accounts
            .iter()
            .map(|(address, account)| AccountSnapshot {
                address: address.clone(),
                balance: account.balance,
                storage_balance: account.storage_balance,
                compute_balance: account.compute_balance,
                dns_balance: account.dns_balance,
                nonce: account.nonce,
                locked_balance: account.locked_balance,
            })
            .collect();

        LedgerSnapshot {
            chain_id: self.chain_id.clone(),
            height: self.height,
            last_block_hash: self.last_block_hash.clone(),
            accounts,
        }
    }

    pub fn scheduled_proposer(&self, next_height: u64) -> &Address {
        self.scheduled_proposer_for_view(next_height, 0)
    }

    pub fn scheduled_proposer_for_view(&self, next_height: u64, view: u64) -> &Address {
        let index = ((next_height - 1) as usize) % self.validators.len();
        let index = (index + (view as usize % self.validators.len())) % self.validators.len();
        &self.validators[index]
    }

    pub fn required_block_approvals(&self) -> usize {
        (self.validators.len() / 2) + 1
    }

    pub fn spendable_balance(&self, address: &str) -> u64 {
        let account = self.account(address);
        account.balance.saturating_sub(account.locked_balance)
    }

    pub fn effective_compute_replication(&self, spec: &ComputeJobSpec) -> u64 {
        usize::from(spec.replication)
            .max(self.min_health_receipts)
            .min(self.validators.len()) as u64
    }

    pub fn compute_request_cost(&self, spec: &ComputeJobSpec) -> Result<u64> {
        compute_job_cost_for_replication(spec, self.effective_compute_replication(spec))
    }

    pub fn is_finalized_health_check(&self, tx_hash: &str) -> bool {
        self.finalized_health_check_ids.contains(tx_hash)
            || self.finalized_health_checks.contains_key(tx_hash)
            || self.finalized_browser_check_ids.contains(tx_hash)
            || self.finalized_browser_checks.contains_key(tx_hash)
            || self.finalized_compute_job_ids.contains(tx_hash)
            || self.finalized_compute_jobs.contains_key(tx_hash)
    }

    pub fn finalized_health_check_count(&self) -> usize {
        self.finalized_health_check_ids
            .len()
            .max(self.finalized_health_checks.len())
    }

    pub fn validate_transaction_basic(&self, tx: &SignedTransaction) -> Result<()> {
        verify_transaction(tx)?;

        if tx.body.chain_id != self.chain_id {
            bail!("transaction is for a different chain");
        }

        let account = self.account(&tx.signer);
        if tx.body.nonce == 0 {
            bail!("transaction nonce must start at 1");
        }
        if tx.body.nonce <= account.nonce {
            bail!("transaction nonce is stale");
        }

        match &tx.body.kind {
            TransactionKind::Transfer { to, amount } => {
                if to.is_empty() {
                    bail!("transfer target cannot be empty");
                }
                if *amount == 0 {
                    bail!("transfer amount must be greater than zero");
                }
            }
            TransactionKind::StorageTransfer { to, amount } => {
                if to.is_empty() {
                    bail!("storage transfer target cannot be empty");
                }
                if *amount == 0 {
                    bail!("storage transfer amount must be greater than zero");
                }
            }
            TransactionKind::ComputeTransfer { to, amount } => {
                if to.is_empty() {
                    bail!("compute transfer target cannot be empty");
                }
                if *amount == 0 {
                    bail!("compute transfer amount must be greater than zero");
                }
            }
            TransactionKind::DnsTransfer { to, amount } => {
                if to.is_empty() {
                    bail!("dns transfer target cannot be empty");
                }
                if *amount == 0 {
                    bail!("dns transfer amount must be greater than zero");
                }
            }
            TransactionKind::HealthCheck { spec } => {
                validate_health_check_spec(spec)?;
                let _ = health_check_cost(spec)?;
            }
            TransactionKind::BrowserCheck { spec } => {
                validate_browser_check_spec(spec)?;
                let _ = browser_check_cost(spec)?;
            }
            TransactionKind::ComputeJob { spec } => {
                validate_compute_job_spec(spec)?;
                self.validate_compute_storage_refs(spec)?;
                let _ = self.compute_request_cost(spec)?;
            }
            TransactionKind::SwapLock { quote } => {
                verify_swap_quote(quote)?;
                if quote.quote.chain_id != self.chain_id {
                    bail!("swap quote is for a different chain");
                }
                if quote.quote.wallet != tx.signer {
                    bail!("swap lock signer does not match the quoted wallet");
                }
                if quote.quote.side != crate::protocol::SwapSide::Sell {
                    bail!("swap locking is only supported for sell quotes");
                }
                if !self.validators.contains(&quote.quoted_by) {
                    bail!("swap quote signer is not a validator");
                }
            }
            TransactionKind::SwapCancel { quote_id } => {
                if quote_id.trim().is_empty() {
                    bail!("swap cancel quote_id cannot be empty");
                }
            }
            TransactionKind::SwapSettle { quote_id } => {
                if quote_id.trim().is_empty() {
                    bail!("swap settle quote_id cannot be empty");
                }
                if tx.signer != self.treasury {
                    bail!("only the treasury validator may settle swap locks");
                }
            }
            TransactionKind::MonitorCreate {
                spec,
                initial_budget,
            } => {
                validate_monitor_spec(spec)?;
                if self.monitors.contains_key(&spec.monitor_id) {
                    bail!("monitor_id already exists");
                }
                if *initial_budget == 0 {
                    bail!("initial monitor budget must be greater than zero");
                }
            }
            TransactionKind::MonitorUpdate { monitor_id, spec } => {
                if monitor_id.trim().is_empty() {
                    bail!("monitor_id cannot be empty");
                }
                validate_monitor_spec(spec)?;
                if spec.monitor_id != *monitor_id {
                    bail!("monitor update monitor_id mismatch");
                }
                let monitor = self
                    .monitors
                    .get(monitor_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown monitor {monitor_id}"))?;
                if monitor.owner != tx.signer {
                    bail!("only the monitor owner may update a monitor");
                }
            }
            TransactionKind::MonitorPause { monitor_id }
            | TransactionKind::MonitorResume { monitor_id }
            | TransactionKind::MonitorDelete { monitor_id } => {
                if monitor_id.trim().is_empty() {
                    bail!("monitor_id cannot be empty");
                }
                let monitor = self
                    .monitors
                    .get(monitor_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown monitor {monitor_id}"))?;
                if monitor.owner != tx.signer {
                    bail!("only the monitor owner may modify a monitor");
                }
            }
            TransactionKind::MonitorTopUp { monitor_id, amount } => {
                if monitor_id.trim().is_empty() {
                    bail!("monitor_id cannot be empty");
                }
                if *amount == 0 {
                    bail!("monitor top up amount must be greater than zero");
                }
                let monitor = self
                    .monitors
                    .get(monitor_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown monitor {monitor_id}"))?;
                if monitor.owner != tx.signer {
                    bail!("only the monitor owner may top up a monitor");
                }
            }
            TransactionKind::StorageCreate {
                spec,
                prepaid_balance,
            } => {
                validate_storage_contract_spec(spec)?;
                if self.storage_contracts.contains_key(&spec.contract_id) {
                    bail!("storage contract_id already exists");
                }
                if spec.host == tx.signer {
                    bail!("storage host must be a different address from the owner");
                }
                if *prepaid_balance == 0 {
                    bail!("storage prepaid_balance must be greater than zero");
                }
            }
            TransactionKind::StorageTopUp {
                contract_id,
                amount,
            } => {
                if contract_id.trim().is_empty() {
                    bail!("storage contract_id cannot be empty");
                }
                if *amount == 0 {
                    bail!("storage top up amount must be greater than zero");
                }
                let contract = self
                    .storage_contracts
                    .get(contract_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown storage contract {contract_id}"))?;
                if contract.owner != tx.signer {
                    bail!("only the storage contract owner may top up storage");
                }
                if !matches!(
                    contract.status,
                    StorageContractStatus::Active | StorageContractStatus::InsufficientFunds
                ) {
                    bail!("storage top up is only valid for active contracts");
                }
            }
            TransactionKind::StorageCancel { contract_id } => {
                if contract_id.trim().is_empty() {
                    bail!("storage contract_id cannot be empty");
                }
                let contract = self
                    .storage_contracts
                    .get(contract_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown storage contract {contract_id}"))?;
                if contract.owner != tx.signer {
                    bail!("only the storage contract owner may cancel storage");
                }
                if !matches!(
                    contract.status,
                    StorageContractStatus::Active | StorageContractStatus::InsufficientFunds
                ) {
                    bail!("storage contract is already terminal");
                }
            }
            TransactionKind::DomainOfferingCreate {
                offering_id,
                suffix,
                gateway_url,
            } => {
                if !self.validators.contains(&tx.signer) {
                    bail!("only validators may create domain offerings");
                }
                validate_domain_offering_input(offering_id, suffix, gateway_url)?;
                if self.domain_offerings.contains_key(offering_id) {
                    bail!("domain offering_id already exists");
                }
                if self
                    .domain_offerings
                    .values()
                    .any(|offering| offering.suffix == *suffix)
                {
                    bail!("domain suffix already has an offering");
                }
            }
            TransactionKind::DomainOfferingPause { offering_id }
            | TransactionKind::DomainOfferingResume { offering_id }
            | TransactionKind::DomainOfferingRetire { offering_id } => {
                if offering_id.trim().is_empty() {
                    bail!("domain offering_id cannot be empty");
                }
                let offering = self
                    .domain_offerings
                    .get(offering_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown domain offering {offering_id}"))?;
                if offering.validator != tx.signer {
                    bail!("only the offering validator may modify a domain offering");
                }
            }
            TransactionKind::DomainLeaseCreate {
                offering_id,
                label,
                target_contract_id,
                duration_secs,
            } => {
                validate_domain_label(label)?;
                let _ = dns_lease_cost(*duration_secs)?;
                let offering = self
                    .domain_offerings
                    .get(offering_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown domain offering {offering_id}"))?;
                if !matches!(offering.status, DomainOfferingStatus::Active) {
                    bail!("domain offering is not active");
                }
                let contract = self
                    .storage_contracts
                    .get(target_contract_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unknown storage contract {target_contract_id}")
                    })?;
                if contract.owner != tx.signer {
                    bail!("domain lease target storage contract must be owned by the signer");
                }
                if !matches!(contract.spec.mode, StorageMode::PublicRaw { .. }) {
                    bail!("domain leases can only target public raw storage contracts");
                }
                let fqdn = domain_fqdn(label, &offering.suffix)?;
                if self.domain_leases.values().any(|lease| {
                    lease.fqdn == fqdn
                        && matches!(
                            lease.status,
                            DomainLeaseStatus::Active | DomainLeaseStatus::InsufficientFunds
                        )
                }) {
                    bail!("domain label is already leased");
                }
            }
            TransactionKind::DomainLeaseRenew {
                lease_id,
                duration_secs,
            } => {
                let _ = dns_lease_cost(*duration_secs)?;
                let lease = self
                    .domain_leases
                    .get(lease_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown domain lease {lease_id}"))?;
                if lease.owner != tx.signer {
                    bail!("only the domain lease owner may renew");
                }
                if matches!(
                    lease.status,
                    DomainLeaseStatus::Cancelled | DomainLeaseStatus::Expired
                ) {
                    bail!("domain lease is terminal");
                }
            }
            TransactionKind::DomainLeaseBind {
                lease_id,
                target_contract_id,
            } => {
                let lease = self
                    .domain_leases
                    .get(lease_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown domain lease {lease_id}"))?;
                if lease.owner != tx.signer {
                    bail!("only the domain lease owner may bind");
                }
                if !matches!(lease.status, DomainLeaseStatus::Active) {
                    bail!("domain lease is not active");
                }
                let contract = self
                    .storage_contracts
                    .get(target_contract_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unknown storage contract {target_contract_id}")
                    })?;
                if contract.owner != tx.signer {
                    bail!("domain lease target storage contract must be owned by the signer");
                }
                if !matches!(contract.spec.mode, StorageMode::PublicRaw { .. }) {
                    bail!("domain leases can only target public raw storage contracts");
                }
            }
            TransactionKind::DomainLeaseCancel { lease_id } => {
                let lease = self
                    .domain_leases
                    .get(lease_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown domain lease {lease_id}"))?;
                if lease.owner != tx.signer {
                    bail!("only the domain lease owner may cancel");
                }
                if !matches!(
                    lease.status,
                    DomainLeaseStatus::Active | DomainLeaseStatus::InsufficientFunds
                ) {
                    bail!("domain lease is already terminal");
                }
            }
        }

        Ok(())
    }

    fn validate_compute_storage_refs(&self, spec: &ComputeJobSpec) -> Result<()> {
        let Some(module_ref) = compute_wasi_module_ref(&spec.workload) else {
            return Ok(());
        };
        let contract = self
            .storage_contracts
            .get(&module_ref.contract_id)
            .ok_or_else(|| anyhow!("compute module_ref references an unknown storage contract"))?;
        if contract.status != StorageContractStatus::Active {
            bail!("compute module_ref references an inactive storage contract");
        }
        if !matches!(contract.spec.mode, StorageMode::PublicRaw { .. }) {
            bail!("compute module_ref storage contract must be public_raw");
        }
        if contract.spec.merkle_root != module_ref.merkle_root {
            bail!("compute module_ref merkle_root does not match storage contract");
        }
        if module_ref.size_bytes > contract.spec.size_bytes {
            bail!("compute module_ref size exceeds storage contract size");
        }
        Ok(())
    }

    pub fn validate_block_proposal(&self, block: &SignedBlock) -> Result<()> {
        verify_block(block)?;
        if block.body.chain_id != self.chain_id {
            bail!("block is for a different chain");
        }
        if block.body.height != self.height + 1 {
            bail!("unexpected block height");
        }
        if block.body.previous_hash != self.last_block_hash {
            bail!("block previous hash does not match local head");
        }
        if &block.body.proposer
            != self.scheduled_proposer_for_view(block.body.height, block.body.view)
        {
            bail!("block proposer is not scheduled for this height and view");
        }
        validate_block_body_limits(&block.body)?;
        self.simulate_apply(&block.body)?;
        Ok(())
    }

    pub fn validate_block(&self, block: &SignedBlock) -> Result<()> {
        self.validate_block_proposal(block)?;
        let approvals = self.validate_block_approvals(block)?;
        if approvals.len() < self.required_block_approvals() {
            bail!(
                "block requires at least {} validator approvals",
                self.required_block_approvals()
            );
        }
        Ok(())
    }

    pub fn apply_block(&mut self, block: &SignedBlock) -> Result<()> {
        self.validate_block(block)?;
        self.apply_block_body(&block.body)?;
        self.height = block.body.height;
        self.last_block_hash = block.hash.clone();
        self.block_history.push(block.hash.clone());
        Ok(())
    }

    pub fn simulate_apply(&self, body: &BlockBody) -> Result<Self> {
        let mut cloned = self.clone();
        cloned.apply_block_body(body)?;
        Ok(cloned)
    }

    fn apply_block_body(&mut self, body: &BlockBody) -> Result<()> {
        let mut tx_to_receipts = BTreeMap::new();
        for batch in &body.health_batches {
            tx_to_receipts.insert(batch.tx_hash.clone(), batch.receipts.clone());
        }
        let mut tx_to_browser_receipts = BTreeMap::new();
        for batch in &body.browser_batches {
            tx_to_browser_receipts.insert(batch.tx_hash.clone(), batch.receipts.clone());
        }
        let mut tx_to_compute_receipts = BTreeMap::new();
        for batch in &body.compute_batches {
            tx_to_compute_receipts.insert(batch.tx_hash.clone(), batch.receipts.clone());
        }
        let mut monitor_browser_batches = BTreeMap::new();
        for batch in &body.monitor_browser_batches {
            monitor_browser_batches.insert(
                (batch.monitor_id.clone(), batch.slot_key.clone()),
                batch.clone(),
            );
        }
        let mut confirmation_batches = BTreeMap::new();
        for batch in &body.confirmation_batches {
            confirmation_batches.insert(
                (batch.monitor_id.clone(), batch.slot_key.clone()),
                batch.clone(),
            );
        }
        self.settle_domain_leases(body.proposed_at)?;

        for tx in &body.transactions {
            self.validate_transaction_basic(tx)?;
            let current_account = self.account(&tx.signer);
            if tx.body.nonce != current_account.nonce + 1 {
                bail!("block contains non-sequential nonce for {}", tx.signer);
            }

            match &tx.body.kind {
                TransactionKind::Transfer { to, amount } => {
                    if self.spendable_balance(&tx.signer) < *amount {
                        bail!("insufficient balance for transfer");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.balance -= amount;
                        account.nonce += 1;
                    }
                    self.accounts.entry(to.clone()).or_default().balance += amount;
                }
                TransactionKind::StorageTransfer { to, amount } => {
                    if self.account(&tx.signer).storage_balance < *amount {
                        bail!("insufficient storage token balance for transfer");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.storage_balance -= amount;
                        account.nonce += 1;
                    }
                    self.accounts.entry(to.clone()).or_default().storage_balance += amount;
                }
                TransactionKind::ComputeTransfer { to, amount } => {
                    if self.account(&tx.signer).compute_balance < *amount {
                        bail!("insufficient compute token balance for transfer");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.compute_balance -= amount;
                        account.nonce += 1;
                    }
                    self.accounts.entry(to.clone()).or_default().compute_balance += amount;
                }
                TransactionKind::DnsTransfer { to, amount } => {
                    if self.account(&tx.signer).dns_balance < *amount {
                        bail!("insufficient dns token balance for transfer");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.dns_balance -= amount;
                        account.nonce += 1;
                    }
                    self.accounts.entry(to.clone()).or_default().dns_balance += amount;
                }
                TransactionKind::HealthCheck { .. } => {
                    let request_cost = match &tx.body.kind {
                        TransactionKind::HealthCheck { spec } => health_check_cost(spec)?,
                        _ => unreachable!(),
                    };
                    if self.spendable_balance(&tx.signer) < request_cost {
                        bail!("insufficient balance for health check");
                    }

                    let receipts = tx_to_receipts.get(&tx.hash).cloned().ok_or_else(|| {
                        anyhow::anyhow!("missing receipts for health check {}", tx.hash)
                    })?;
                    let unique_valid_receipts =
                        self.validate_health_receipts_for_tx(tx, &receipts)?;
                    if unique_valid_receipts.len() < self.min_health_receipts {
                        bail!(
                            "health check {} requires at least {} validator receipts",
                            tx.hash,
                            self.min_health_receipts
                        );
                    }
                    let rewarded_receipts =
                        self.select_consensus_health_receipts(&unique_valid_receipts)?;

                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.balance -= request_cost;
                        account.nonce += 1;
                    }

                    let reward_per_validator = request_cost / rewarded_receipts.len() as u64;
                    let distributed = reward_per_validator * rewarded_receipts.len() as u64;
                    let remainder = request_cost - distributed;

                    for receipt in &rewarded_receipts {
                        self.accounts
                            .entry(receipt.body.executor.clone())
                            .or_default()
                            .balance += reward_per_validator;
                    }
                    self.accounts
                        .entry(self.treasury.clone())
                        .or_default()
                        .balance += remainder;

                    let success_count = rewarded_receipts
                        .iter()
                        .filter(|receipt| receipt.body.success)
                        .count();
                    let failure_count = rewarded_receipts.len() - success_count;
                    let divergent_count = unique_valid_receipts
                        .len()
                        .saturating_sub(rewarded_receipts.len());
                    self.finalized_health_checks.insert(
                        tx.hash.clone(),
                        FinalizedHealthCheck {
                            tx_hash: tx.hash.clone(),
                            requester: tx.signer.clone(),
                            finalized_at: body.proposed_at,
                            receipts: unique_valid_receipts,
                            rewarded_receipts: rewarded_receipts.clone(),
                            consensus_success: rewarded_receipts
                                .first()
                                .map(|receipt| receipt.body.success)
                                .unwrap_or(false),
                            success_count,
                            failure_count,
                            divergent_count,
                            requester_cost: request_cost,
                        },
                    );
                    self.finalized_health_check_ids.insert(tx.hash.clone());
                }
                TransactionKind::BrowserCheck { spec } => {
                    let request_cost = browser_check_cost(spec)?;
                    if self.spendable_balance(&tx.signer) < request_cost {
                        bail!("insufficient balance for browser check");
                    }

                    let receipts =
                        tx_to_browser_receipts
                            .get(&tx.hash)
                            .cloned()
                            .ok_or_else(|| {
                                anyhow::anyhow!("missing receipts for browser check {}", tx.hash)
                            })?;
                    let unique_valid_receipts =
                        self.validate_browser_receipts_for_tx(tx, &receipts)?;
                    if unique_valid_receipts.len() < self.min_health_receipts {
                        bail!(
                            "browser check {} requires at least {} validator receipts",
                            tx.hash,
                            self.min_health_receipts
                        );
                    }
                    let rewarded_receipts =
                        self.select_consensus_browser_receipts(&unique_valid_receipts)?;

                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.balance -= request_cost;
                        account.nonce += 1;
                    }

                    let reward_per_validator = request_cost / rewarded_receipts.len() as u64;
                    let distributed = reward_per_validator * rewarded_receipts.len() as u64;
                    let remainder = request_cost - distributed;
                    for receipt in &rewarded_receipts {
                        self.accounts
                            .entry(receipt.body.executor.clone())
                            .or_default()
                            .balance += reward_per_validator;
                    }
                    self.accounts
                        .entry(self.treasury.clone())
                        .or_default()
                        .balance += remainder;

                    let success_count = rewarded_receipts
                        .iter()
                        .filter(|receipt| receipt.body.success)
                        .count();
                    let failure_count = rewarded_receipts.len() - success_count;
                    let divergent_count = unique_valid_receipts
                        .len()
                        .saturating_sub(rewarded_receipts.len());
                    self.finalized_browser_checks.insert(
                        tx.hash.clone(),
                        FinalizedBrowserCheck {
                            tx_hash: tx.hash.clone(),
                            requester: tx.signer.clone(),
                            finalized_at: body.proposed_at,
                            receipts: unique_valid_receipts,
                            rewarded_receipts: rewarded_receipts.clone(),
                            consensus_success: rewarded_receipts
                                .first()
                                .map(|receipt| receipt.body.success)
                                .unwrap_or(false),
                            success_count,
                            failure_count,
                            divergent_count,
                            requester_cost: request_cost,
                            package_hash: rewarded_receipts
                                .first()
                                .map(|receipt| receipt.body.package_hash.clone())
                                .unwrap_or_default(),
                            runtime_hash: rewarded_receipts
                                .first()
                                .map(|receipt| receipt.body.runtime_hash.clone())
                                .unwrap_or_default(),
                        },
                    );
                    self.finalized_browser_check_ids.insert(tx.hash.clone());
                }
                TransactionKind::ComputeJob { spec } => {
                    let request_cost = self.compute_request_cost(spec)?;
                    if self.account(&tx.signer).compute_balance < request_cost {
                        bail!("insufficient compute token balance for compute job");
                    }

                    let receipts =
                        tx_to_compute_receipts
                            .get(&tx.hash)
                            .cloned()
                            .ok_or_else(|| {
                                anyhow::anyhow!("missing receipts for compute job {}", tx.hash)
                            })?;
                    let unique_valid_receipts =
                        self.validate_compute_receipts_for_tx(tx, &receipts)?;
                    let required = usize::from(spec.replication)
                        .max(self.min_health_receipts)
                        .min(self.validators.len());
                    if unique_valid_receipts.len() < required {
                        bail!(
                            "compute job {} requires at least {} validator receipts",
                            tx.hash,
                            required
                        );
                    }
                    let rewarded_receipts =
                        self.select_consensus_compute_receipts(&unique_valid_receipts)?;

                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.compute_balance -= request_cost;
                        account.nonce += 1;
                    }

                    let reward_per_validator = request_cost / rewarded_receipts.len() as u64;
                    let distributed = reward_per_validator * rewarded_receipts.len() as u64;
                    let remainder = request_cost - distributed;
                    for receipt in &rewarded_receipts {
                        self.accounts
                            .entry(receipt.body.executor.clone())
                            .or_default()
                            .compute_balance += reward_per_validator;
                    }
                    self.accounts
                        .entry(self.treasury.clone())
                        .or_default()
                        .compute_balance += remainder;

                    let success_count = rewarded_receipts
                        .iter()
                        .filter(|receipt| receipt.body.success)
                        .count();
                    let failure_count = rewarded_receipts.len() - success_count;
                    let divergent_count = unique_valid_receipts
                        .len()
                        .saturating_sub(rewarded_receipts.len());
                    let representative = rewarded_receipts.first();
                    self.finalized_compute_jobs.insert(
                        tx.hash.clone(),
                        FinalizedComputeJob {
                            tx_hash: tx.hash.clone(),
                            requester: tx.signer.clone(),
                            finalized_at: body.proposed_at,
                            receipts: unique_valid_receipts,
                            rewarded_receipts: rewarded_receipts.clone(),
                            consensus_success: representative
                                .map(|receipt| receipt.body.success)
                                .unwrap_or(false),
                            success_count,
                            failure_count,
                            divergent_count,
                            requester_cost: request_cost,
                            job_hash: compute_job_hash(spec)?,
                            reduced_output: representative
                                .and_then(|receipt| receipt.body.reduced_output.clone()),
                        },
                    );
                    self.finalized_compute_job_ids.insert(tx.hash.clone());
                }
                TransactionKind::SwapLock { quote } => {
                    if body.proposed_at >= quote.quote.expires_at {
                        bail!("swap quote expired before it was finalized");
                    }
                    if self.pending_swap_locks.contains_key(&quote.quote.quote_id) {
                        bail!("swap quote is already locked");
                    }
                    if self.spendable_balance(&tx.signer) < quote.quote.token_amount {
                        bail!("insufficient spendable balance for swap lock");
                    }

                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.locked_balance += quote.quote.token_amount;
                        account.nonce += 1;
                    }
                    self.pending_swap_locks.insert(
                        quote.quote.quote_id.clone(),
                        PendingSwapLock {
                            quote: quote.clone(),
                            owner: tx.signer.clone(),
                            locked_at: body.proposed_at,
                        },
                    );
                }
                TransactionKind::SwapCancel { quote_id } => {
                    let pending = self
                        .pending_swap_locks
                        .get(quote_id)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("unknown swap lock {quote_id}"))?;
                    if pending.owner != tx.signer {
                        bail!("only the original wallet may cancel a swap lock");
                    }
                    if body.proposed_at < pending.quote.quote.expires_at {
                        bail!("swap lock cannot be cancelled before its quote expires");
                    }

                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        if account.locked_balance < pending.quote.quote.token_amount {
                            bail!("swap lock exceeds the wallet locked balance");
                        }
                        account.locked_balance -= pending.quote.quote.token_amount;
                        account.nonce += 1;
                    }
                    self.pending_swap_locks.remove(quote_id);
                }
                TransactionKind::SwapSettle { quote_id } => {
                    let pending = self
                        .pending_swap_locks
                        .get(quote_id)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("unknown swap lock {quote_id}"))?;
                    if body.proposed_at > pending.quote.quote.expires_at {
                        bail!("swap lock may not be settled after its quote expires");
                    }

                    {
                        let owner = self.accounts.entry(pending.owner.clone()).or_default();
                        if owner.locked_balance < pending.quote.quote.token_amount {
                            bail!("swap lock exceeds the wallet locked balance");
                        }
                        if owner.balance < pending.quote.quote.token_amount {
                            bail!("swap lock exceeds the wallet balance");
                        }
                        owner.balance -= pending.quote.quote.token_amount;
                        owner.locked_balance -= pending.quote.quote.token_amount;
                    }
                    {
                        let treasury = self.accounts.entry(self.treasury.clone()).or_default();
                        treasury.balance += pending.quote.quote.token_amount;
                        treasury.nonce += 1;
                    }
                    self.pending_swap_locks.remove(quote_id);
                }
                TransactionKind::MonitorCreate {
                    spec,
                    initial_budget,
                } => {
                    if self.spendable_balance(&tx.signer) < *initial_budget {
                        bail!("insufficient balance for monitor create");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.balance -= initial_budget;
                        account.nonce += 1;
                    }
                    let now = body.proposed_at;
                    let status = monitor_ready_status(false, spec, *initial_budget);
                    self.monitors.insert(
                        spec.monitor_id.clone(),
                        MonitorRecord {
                            monitor_id: spec.monitor_id.clone(),
                            owner: tx.signer.clone(),
                            spec: spec.clone(),
                            budget_balance: *initial_budget,
                            status,
                            paused: false,
                            created_at: now,
                            updated_at: now,
                            next_slot_hint: schedule_next_slot_start(&spec.schedule, now)
                                .ok()
                                .map(|value| value.to_rfc3339()),
                            last_observation_at: None,
                        },
                    );
                }
                TransactionKind::MonitorUpdate { monitor_id, spec } => {
                    let monitor = self
                        .monitors
                        .get_mut(monitor_id)
                        .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
                    monitor.spec = spec.clone();
                    monitor.updated_at = body.proposed_at;
                    monitor.next_slot_hint =
                        schedule_next_slot_start(&monitor.spec.schedule, body.proposed_at)
                            .ok()
                            .map(|value| value.to_rfc3339());
                }
                TransactionKind::MonitorPause { monitor_id } => {
                    let monitor = self
                        .monitors
                        .get_mut(monitor_id)
                        .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
                    monitor.paused = true;
                    monitor.status = MonitorStatus::Paused;
                    monitor.updated_at = body.proposed_at;
                }
                TransactionKind::MonitorResume { monitor_id } => {
                    let monitor = self
                        .monitors
                        .get_mut(monitor_id)
                        .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
                    monitor.paused = false;
                    monitor.status =
                        monitor_ready_status(false, &monitor.spec, monitor.budget_balance);
                    monitor.updated_at = body.proposed_at;
                    monitor.next_slot_hint =
                        schedule_next_slot_start(&monitor.spec.schedule, body.proposed_at)
                            .ok()
                            .map(|value| value.to_rfc3339());
                }
                TransactionKind::MonitorTopUp { monitor_id, amount } => {
                    if self.spendable_balance(&tx.signer) < *amount {
                        bail!("insufficient balance for monitor top up");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.balance -= amount;
                        account.nonce += 1;
                    }
                    let monitor = self
                        .monitors
                        .get_mut(monitor_id)
                        .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
                    monitor.budget_balance += amount;
                    monitor.status =
                        monitor_ready_status(monitor.paused, &monitor.spec, monitor.budget_balance);
                    monitor.updated_at = body.proposed_at;
                }
                TransactionKind::MonitorDelete { monitor_id } => {
                    let monitor = self
                        .monitors
                        .remove(monitor_id)
                        .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
                    self.accounts
                        .entry(monitor.owner.clone())
                        .or_default()
                        .balance += monitor.budget_balance;
                    self.monitor_slot_history.remove(monitor_id);
                }
                TransactionKind::StorageCreate {
                    spec,
                    prepaid_balance,
                } => {
                    if self.account(&tx.signer).storage_balance < *prepaid_balance {
                        bail!("insufficient storage token balance for storage create");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.storage_balance -= prepaid_balance;
                        account.nonce += 1;
                    }
                    let created_at = body.proposed_at;
                    self.storage_contracts.insert(
                        spec.contract_id.clone(),
                        StorageContractRecord {
                            contract_id: spec.contract_id.clone(),
                            owner: tx.signer.clone(),
                            host: spec.host.clone(),
                            spec: spec.clone(),
                            prepaid_balance: *prepaid_balance,
                            status: StorageContractStatus::Active,
                            created_at,
                            expires_at: created_at
                                + chrono::Duration::seconds(spec.duration_secs as i64),
                            last_proven_at: created_at,
                            total_paid: 0,
                            proof_count: 0,
                        },
                    );
                }
                TransactionKind::StorageTopUp {
                    contract_id,
                    amount,
                } => {
                    if self.account(&tx.signer).storage_balance < *amount {
                        bail!("insufficient storage token balance for storage top up");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.storage_balance -= amount;
                        account.nonce += 1;
                    }
                    let contract = self
                        .storage_contracts
                        .get_mut(contract_id)
                        .ok_or_else(|| anyhow!("unknown storage contract {contract_id}"))?;
                    contract.prepaid_balance += amount;
                    if matches!(contract.status, StorageContractStatus::InsufficientFunds) {
                        contract.status = StorageContractStatus::Active;
                    }
                }
                TransactionKind::StorageCancel { contract_id } => {
                    let contract = self
                        .storage_contracts
                        .get_mut(contract_id)
                        .ok_or_else(|| anyhow!("unknown storage contract {contract_id}"))?;
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.nonce += 1;
                        account.storage_balance += contract.prepaid_balance;
                    }
                    contract.prepaid_balance = 0;
                    contract.status = StorageContractStatus::Cancelled;
                }
                TransactionKind::DomainOfferingCreate {
                    offering_id,
                    suffix,
                    gateway_url,
                } => {
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    self.domain_offerings.insert(
                        offering_id.clone(),
                        DomainOfferingRecord {
                            offering_id: offering_id.clone(),
                            validator: tx.signer.clone(),
                            suffix: suffix.clone(),
                            gateway_url: gateway_url.clone(),
                            isolation_mode: DomainIsolationMode::OpaqueSandbox,
                            status: DomainOfferingStatus::Active,
                            created_at: body.proposed_at,
                            verified_at: Some(body.proposed_at),
                        },
                    );
                }
                TransactionKind::DomainOfferingPause { offering_id } => {
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    let offering = self
                        .domain_offerings
                        .get_mut(offering_id)
                        .ok_or_else(|| anyhow!("unknown domain offering {offering_id}"))?;
                    if matches!(offering.status, DomainOfferingStatus::Retired) {
                        bail!("retired domain offerings cannot be paused");
                    }
                    offering.status = DomainOfferingStatus::Paused;
                }
                TransactionKind::DomainOfferingResume { offering_id } => {
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    let offering = self
                        .domain_offerings
                        .get_mut(offering_id)
                        .ok_or_else(|| anyhow!("unknown domain offering {offering_id}"))?;
                    if !matches!(
                        offering.status,
                        DomainOfferingStatus::Paused | DomainOfferingStatus::PendingSetup
                    ) {
                        bail!("domain offering cannot be resumed");
                    }
                    offering.status = DomainOfferingStatus::Active;
                    offering.verified_at.get_or_insert(body.proposed_at);
                }
                TransactionKind::DomainOfferingRetire { offering_id } => {
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    let offering = self
                        .domain_offerings
                        .get_mut(offering_id)
                        .ok_or_else(|| anyhow!("unknown domain offering {offering_id}"))?;
                    offering.status = DomainOfferingStatus::Retired;
                }
                TransactionKind::DomainLeaseCreate {
                    offering_id,
                    label,
                    target_contract_id,
                    duration_secs,
                } => {
                    let cost = dns_lease_cost(*duration_secs)?;
                    if self.account(&tx.signer).dns_balance < cost {
                        bail!("insufficient dns token balance for domain lease");
                    }
                    let offering = self
                        .domain_offerings
                        .get(offering_id)
                        .ok_or_else(|| anyhow!("unknown domain offering {offering_id}"))?;
                    let fqdn = domain_fqdn(label, &offering.suffix)?;
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.dns_balance -= cost;
                        account.nonce += 1;
                    }
                    let starts_at = body.proposed_at;
                    let expires_at = starts_at + chrono::Duration::seconds(*duration_secs as i64);
                    let lease_id = compute_hash(&(
                        "domain-lease-v1",
                        &self.chain_id,
                        offering_id,
                        label,
                        &tx.signer,
                        starts_at,
                    ))?;
                    self.domain_leases.insert(
                        lease_id.clone(),
                        DomainLeaseRecord {
                            lease_id,
                            offering_id: offering_id.clone(),
                            owner: tx.signer.clone(),
                            label: label.clone(),
                            fqdn,
                            target_contract_id: target_contract_id.clone(),
                            prepaid_balance: cost,
                            starts_at,
                            expires_at,
                            last_paid_at: starts_at,
                            status: DomainLeaseStatus::Active,
                            created_at: starts_at,
                            updated_at: starts_at,
                        },
                    );
                }
                TransactionKind::DomainLeaseRenew {
                    lease_id,
                    duration_secs,
                } => {
                    let cost = dns_lease_cost(*duration_secs)?;
                    if self.account(&tx.signer).dns_balance < cost {
                        bail!("insufficient dns token balance for domain lease renew");
                    }
                    {
                        let account = self.accounts.entry(tx.signer.clone()).or_default();
                        account.dns_balance -= cost;
                        account.nonce += 1;
                    }
                    let lease = self
                        .domain_leases
                        .get_mut(lease_id)
                        .ok_or_else(|| anyhow!("unknown domain lease {lease_id}"))?;
                    lease.prepaid_balance = lease
                        .prepaid_balance
                        .checked_add(cost)
                        .ok_or_else(|| anyhow!("domain lease prepaid balance overflow"))?;
                    let base = if lease.expires_at > body.proposed_at {
                        lease.expires_at
                    } else {
                        body.proposed_at
                    };
                    lease.expires_at = base + chrono::Duration::seconds(*duration_secs as i64);
                    lease.updated_at = body.proposed_at;
                    if matches!(lease.status, DomainLeaseStatus::InsufficientFunds) {
                        lease.status = DomainLeaseStatus::Active;
                        lease.last_paid_at = body.proposed_at;
                    }
                }
                TransactionKind::DomainLeaseBind {
                    lease_id,
                    target_contract_id,
                } => {
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    let lease = self
                        .domain_leases
                        .get_mut(lease_id)
                        .ok_or_else(|| anyhow!("unknown domain lease {lease_id}"))?;
                    lease.target_contract_id = target_contract_id.clone();
                    lease.updated_at = body.proposed_at;
                }
                TransactionKind::DomainLeaseCancel { lease_id } => {
                    let lease = self
                        .domain_leases
                        .get_mut(lease_id)
                        .ok_or_else(|| anyhow!("unknown domain lease {lease_id}"))?;
                    let refund = lease.prepaid_balance;
                    lease.prepaid_balance = 0;
                    lease.status = DomainLeaseStatus::Cancelled;
                    lease.updated_at = body.proposed_at;
                    let account = self.accounts.entry(tx.signer.clone()).or_default();
                    account.nonce += 1;
                    account.dns_balance += refund;
                }
            }
        }

        self.apply_storage_proof_batches(
            &body.storage_proof_batches,
            &body.previous_hash,
            body.proposed_at,
        )?;
        let observations_by_slot =
            self.apply_heartbeat_observations(&body.heartbeat_observations, body.proposed_at)?;
        self.apply_monitor_browser_batches(&body.monitor_browser_batches, body.proposed_at)?;
        self.apply_monitor_evaluations(
            &body.monitor_evaluations,
            &observations_by_slot,
            &monitor_browser_batches,
            &confirmation_batches,
            body.proposed_at,
        )?;

        Ok(())
    }

    fn settle_domain_leases(&mut self, proposed_at: DateTime<Utc>) -> Result<()> {
        let lease_ids = self.domain_leases.keys().cloned().collect::<Vec<_>>();
        for lease_id in lease_ids {
            let Some(snapshot) = self.domain_leases.get(&lease_id).cloned() else {
                continue;
            };
            if !matches!(
                snapshot.status,
                DomainLeaseStatus::Active | DomainLeaseStatus::InsufficientFunds
            ) {
                continue;
            }
            let window_end = proposed_at.min(snapshot.expires_at);
            if window_end <= snapshot.last_paid_at {
                continue;
            }
            let elapsed_secs = window_end
                .signed_duration_since(snapshot.last_paid_at)
                .num_seconds();
            if elapsed_secs <= 0 {
                continue;
            }
            let amount_due = (elapsed_secs as u64)
                .checked_mul(DNS_LEASE_COST_PER_SUBDOMAIN_SECOND)
                .ok_or_else(|| anyhow!("domain lease settlement overflow"))?;
            let paid = amount_due.min(snapshot.prepaid_balance);
            let offering = self
                .domain_offerings
                .get(&snapshot.offering_id)
                .ok_or_else(|| anyhow!("unknown domain offering {}", snapshot.offering_id))?;
            if paid > 0 {
                self.accounts
                    .entry(offering.validator.clone())
                    .or_default()
                    .dns_balance += paid;
            }
            let lease = self
                .domain_leases
                .get_mut(&lease_id)
                .ok_or_else(|| anyhow!("unknown domain lease {lease_id}"))?;
            lease.prepaid_balance -= paid;
            lease.last_paid_at = window_end;
            lease.updated_at = proposed_at;
            if paid < amount_due {
                lease.status = DomainLeaseStatus::InsufficientFunds;
            } else if window_end >= lease.expires_at {
                lease.status = DomainLeaseStatus::Expired;
            } else if lease.prepaid_balance > 0 {
                lease.status = DomainLeaseStatus::Active;
            }
        }
        Ok(())
    }

    fn validate_health_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedHealthReceipt],
    ) -> Result<Vec<SignedHealthReceipt>> {
        let TransactionKind::HealthCheck { spec } = &tx.body.kind else {
            bail!("receipt batches are only valid for health check transactions");
        };
        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in receipts {
            verify_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("receipt is for a different chain");
            }
            if receipt.body.tx_hash != tx.hash {
                bail!("receipt tx hash mismatch");
            }
            if receipt.body.request_id != spec.request_id {
                bail!("receipt request_id mismatch");
            }
            if !self.validators.contains(&receipt.body.executor) {
                bail!("receipt signer is not a validator");
            }
            if seen.insert(receipt.body.executor.clone()) {
                validated.push(receipt.clone());
            }
        }

        Ok(validated)
    }

    fn validate_browser_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedBrowserReceipt],
    ) -> Result<Vec<SignedBrowserReceipt>> {
        let TransactionKind::BrowserCheck { spec } = &tx.body.kind else {
            bail!("browser receipt batches are only valid for browser check transactions");
        };
        let package_hash = crate::browser::browser_package_hash(&spec.package)?;
        let runtime_hash = crate::browser::browser_runtime_hash(&spec.package.runtime)?;
        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in receipts {
            verify_browser_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("browser receipt is for a different chain");
            }
            if receipt.body.tx_hash != tx.hash {
                bail!("browser receipt tx hash mismatch");
            }
            if receipt.body.request_id != spec.request_id {
                bail!("browser receipt request_id mismatch");
            }
            if receipt.body.package_hash != package_hash {
                bail!("browser receipt package_hash mismatch");
            }
            if receipt.body.runtime_hash != runtime_hash {
                bail!("browser receipt runtime_hash mismatch");
            }
            if !self.validators.contains(&receipt.body.executor) {
                bail!("browser receipt signer is not a validator");
            }
            if seen.insert(receipt.body.executor.clone()) {
                validated.push(receipt.clone());
            }
        }
        Ok(validated)
    }

    fn validate_compute_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedComputeReceipt],
    ) -> Result<Vec<SignedComputeReceipt>> {
        let TransactionKind::ComputeJob { spec } = &tx.body.kind else {
            bail!("compute receipt batches are only valid for compute job transactions");
        };
        let job_hash = compute_job_hash(spec)?;
        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in receipts {
            verify_compute_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("compute receipt is for a different chain");
            }
            if receipt.body.tx_hash != tx.hash {
                bail!("compute receipt tx hash mismatch");
            }
            if receipt.body.request_id != spec.request_id {
                bail!("compute receipt request_id mismatch");
            }
            if receipt.body.job_hash != job_hash {
                bail!("compute receipt job_hash mismatch");
            }
            if !self.validators.contains(&receipt.body.executor) {
                bail!("compute receipt signer is not a validator");
            }
            for output in &receipt.body.shard_outputs {
                validate_compute_output(output)?;
                validate_compute_output_artifacts(&spec.artifact_policy, output)?;
            }
            let reduced = if receipt.body.success {
                Some(reduce_compute_outputs(spec, &receipt.body.shard_outputs)?)
            } else {
                None
            };
            if receipt.body.success && receipt.body.reduced_output != reduced {
                bail!("compute receipt reduced output mismatch");
            }
            if seen.insert(receipt.body.executor.clone()) {
                validated.push(receipt.clone());
            }
        }
        Ok(validated)
    }

    fn validate_block_approvals(&self, block: &SignedBlock) -> Result<Vec<SignedBlockApproval>> {
        let mut seen = BTreeSet::new();
        let mut approvals = Vec::new();
        for approval in &block.approvals {
            verify_block_approval(approval)?;
            if approval.body.chain_id != self.chain_id {
                bail!("block approval is for a different chain");
            }
            if approval.body.height != block.body.height {
                bail!("block approval height mismatch");
            }
            if approval.body.view != block.body.view {
                bail!("block approval view mismatch");
            }
            if approval.body.previous_hash != block.body.previous_hash {
                bail!("block approval previous hash mismatch");
            }
            if approval.body.block_hash != block.hash {
                bail!("block approval block hash mismatch");
            }
            if !self.validators.contains(&approval.body.approver) {
                bail!("block approval signer is not a validator");
            }
            if seen.insert(approval.body.approver.clone()) {
                approvals.push(approval.clone());
            }
        }
        Ok(approvals)
    }

    fn select_consensus_health_receipts(
        &self,
        receipts: &[SignedHealthReceipt],
    ) -> Result<Vec<SignedHealthReceipt>> {
        let mut clusters: BTreeMap<String, Vec<SignedHealthReceipt>> = BTreeMap::new();
        for receipt in receipts {
            let outcome_key = health_outcome_key(receipt)?;
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
            bail!("health check is missing validated receipts");
        };
        if tied {
            bail!("health receipts do not reach a unique consensus outcome");
        }

        let winning_cluster = clusters.remove(&best_key).unwrap_or_default();
        if winning_cluster.len() * 2 <= receipts.len() {
            bail!("health receipts do not reach majority consensus");
        }
        Ok(winning_cluster)
    }

    fn select_consensus_browser_receipts(
        &self,
        receipts: &[SignedBrowserReceipt],
    ) -> Result<Vec<SignedBrowserReceipt>> {
        let mut clusters: BTreeMap<String, Vec<SignedBrowserReceipt>> = BTreeMap::new();
        for receipt in receipts {
            let outcome_key = browser_outcome_key(receipt)?;
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
            bail!("browser check is missing validated receipts");
        };
        if tied {
            bail!("browser receipts do not reach a unique consensus outcome");
        }
        let winning_cluster = clusters.remove(&best_key).unwrap_or_default();
        if winning_cluster.len() * 2 <= receipts.len() {
            bail!("browser receipts do not reach majority consensus");
        }
        Ok(winning_cluster)
    }

    fn select_consensus_compute_receipts(
        &self,
        receipts: &[SignedComputeReceipt],
    ) -> Result<Vec<SignedComputeReceipt>> {
        let mut clusters: BTreeMap<String, Vec<SignedComputeReceipt>> = BTreeMap::new();
        for receipt in receipts {
            let outcome_key = compute_outcome_key(receipt)?;
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
            bail!("compute job is missing validated receipts");
        };
        if tied {
            bail!("compute receipts do not reach a unique consensus outcome");
        }
        let winning_cluster = clusters.remove(&best_key).unwrap_or_default();
        if winning_cluster.len() * 2 <= receipts.len() {
            bail!("compute receipts do not reach majority consensus");
        }
        Ok(winning_cluster)
    }

    pub fn summarize_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedHealthReceipt],
    ) -> Result<BlockHealthBatch> {
        let receipts = self.validate_health_receipts_for_tx(tx, receipts)?;
        Ok(BlockHealthBatch {
            tx_hash: tx.hash.clone(),
            receipts,
        })
    }

    pub fn summarize_browser_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedBrowserReceipt],
    ) -> Result<BlockBrowserBatch> {
        let receipts = self.validate_browser_receipts_for_tx(tx, receipts)?;
        Ok(BlockBrowserBatch {
            tx_hash: tx.hash.clone(),
            receipts,
        })
    }

    pub fn summarize_compute_receipts_for_tx(
        &self,
        tx: &SignedTransaction,
        receipts: &[SignedComputeReceipt],
    ) -> Result<BlockComputeBatch> {
        let receipts = self.validate_compute_receipts_for_tx(tx, receipts)?;
        Ok(BlockComputeBatch {
            tx_hash: tx.hash.clone(),
            receipts,
        })
    }

    pub fn summarize_storage_proof_batch(
        &self,
        contract_id: &str,
        receipts: &[SignedStorageProofReceipt],
        previous_block_hash: &str,
        proposed_at: DateTime<Utc>,
    ) -> Result<StorageProofBatch> {
        let contract = self
            .storage_contracts
            .get(contract_id)
            .ok_or_else(|| anyhow!("unknown storage contract {contract_id}"))?;
        let receipts = self.validate_storage_proof_receipts(
            contract,
            receipts,
            previous_block_hash,
            proposed_at,
        )?;
        Ok(StorageProofBatch {
            contract_id: contract_id.to_string(),
            receipts,
        })
    }

    pub fn summarize_monitor_browser_batch(
        &self,
        monitor: &MonitorRecord,
        slot_key: &str,
        receipts: &[SignedBrowserReceipt],
    ) -> Result<MonitorBrowserBatch> {
        let receipts = self.validate_monitor_browser_receipts(monitor, slot_key, receipts)?;
        Ok(MonitorBrowserBatch {
            monitor_id: monitor.monitor_id.clone(),
            slot_key: slot_key.to_string(),
            receipts,
        })
    }

    fn apply_storage_proof_batches(
        &mut self,
        batches: &[StorageProofBatch],
        previous_block_hash: &str,
        proposed_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut seen_contracts = BTreeSet::new();
        for batch in batches {
            if !seen_contracts.insert(batch.contract_id.clone()) {
                bail!("block contains duplicate storage proof batch");
            }
            let contract = self
                .storage_contracts
                .get(&batch.contract_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown storage contract {}", batch.contract_id))?;
            let valid_receipts = self.validate_storage_proof_receipts(
                &contract,
                &batch.receipts,
                previous_block_hash,
                proposed_at,
            )?;
            if valid_receipts.len() < self.min_health_receipts {
                bail!(
                    "storage contract {} requires at least {} validator proof receipts",
                    batch.contract_id,
                    self.min_health_receipts
                );
            }
            let rewarded_receipts = self.select_consensus_storage_receipts(&valid_receipts)?;
            let winning = rewarded_receipts
                .first()
                .ok_or_else(|| anyhow!("storage proof batch is missing receipts"))?;
            if !winning.body.success {
                bail!("storage proof consensus is not successful");
            }

            let elapsed_secs = winning
                .body
                .window_end
                .signed_duration_since(contract.last_proven_at)
                .num_seconds();
            if elapsed_secs <= 0 {
                bail!("storage proof window does not advance the contract");
            }
            let reward_due = storage_reward_for_elapsed(
                contract.spec.size_bytes,
                elapsed_secs as u64,
                contract.spec.reward_rate_per_64mib_second,
            )?;

            let contract = self
                .storage_contracts
                .get_mut(&batch.contract_id)
                .ok_or_else(|| anyhow!("unknown storage contract {}", batch.contract_id))?;
            let paid = reward_due.min(contract.prepaid_balance);
            contract.prepaid_balance -= paid;
            contract.total_paid += paid;
            contract.last_proven_at = winning.body.window_end;
            contract.proof_count += 1;
            if paid > 0 {
                self.accounts
                    .entry(contract.host.clone())
                    .or_default()
                    .storage_balance += paid;
            }
            if paid < reward_due {
                contract.status = StorageContractStatus::InsufficientFunds;
            }
            if contract.last_proven_at >= contract.expires_at {
                let refund = contract.prepaid_balance;
                contract.prepaid_balance = 0;
                contract.status = StorageContractStatus::Expired;
                if refund > 0 {
                    self.accounts
                        .entry(contract.owner.clone())
                        .or_default()
                        .storage_balance += refund;
                }
            }
        }
        Ok(())
    }

    fn validate_storage_proof_receipts(
        &self,
        contract: &StorageContractRecord,
        receipts: &[SignedStorageProofReceipt],
        previous_block_hash: &str,
        proposed_at: DateTime<Utc>,
    ) -> Result<Vec<SignedStorageProofReceipt>> {
        if !matches!(contract.status, StorageContractStatus::Active) {
            bail!("storage contract is not active");
        }
        let mut seen_validators = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in receipts {
            verify_storage_proof_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("storage proof receipt is for a different chain");
            }
            if receipt.body.contract_id != contract.contract_id {
                bail!("storage proof receipt contract_id mismatch");
            }
            if receipt.body.host != contract.host {
                bail!("storage proof receipt host mismatch");
            }
            if !self.validators.contains(&receipt.body.validator) {
                bail!("storage proof receipt signer is not a validator");
            }
            if receipt.body.window_start != contract.last_proven_at {
                bail!("storage proof receipt window_start mismatch");
            }
            if receipt.body.window_end <= receipt.body.window_start {
                bail!("storage proof receipt window is invalid");
            }
            if receipt.body.window_end > proposed_at {
                bail!("storage proof receipt is from the future");
            }
            if receipt.body.window_end > contract.expires_at {
                bail!("storage proof receipt extends beyond contract expiry");
            }
            let elapsed = receipt
                .body
                .window_end
                .signed_duration_since(receipt.body.window_start)
                .num_seconds();
            if elapsed <= 0 || elapsed as u64 > contract.spec.proof_interval_secs {
                bail!("storage proof receipt window exceeds the contract proof interval");
            }
            if receipt.body.observed_at < receipt.body.window_start
                || receipt.body.observed_at > proposed_at
            {
                bail!("storage proof receipt observed_at is outside the proof window");
            }
            if receipt.body.bytes_stored < contract.spec.size_bytes {
                bail!("storage proof receipt does not cover the contract size");
            }
            if receipt.body.merkle_root != contract.spec.merkle_root {
                bail!("storage proof receipt merkle_root mismatch");
            }
            let expected_seed = storage_challenge_seed(
                &self.chain_id,
                &contract.contract_id,
                previous_block_hash,
                contract.last_proven_at,
                receipt.body.window_end,
                &contract.spec.merkle_root,
            )?;
            if receipt.body.challenge_seed != expected_seed {
                bail!("storage proof receipt challenge_seed mismatch");
            }
            let expected_chunk_indices = storage_challenge_indices(
                &expected_seed,
                storage_chunk_count(&contract.spec),
                contract.spec.proof_sample_count,
            )?;
            if receipt.body.samples.len() != contract.spec.proof_sample_count as usize {
                bail!("storage proof receipt sample count mismatch");
            }
            let actual_indices = receipt
                .body
                .samples
                .iter()
                .map(|sample| sample.chunk_index)
                .collect::<Vec<_>>();
            if actual_indices != expected_chunk_indices {
                bail!("storage proof receipt challenge indices mismatch");
            }
            for sample in &receipt.body.samples {
                validate_storage_proof_sample(sample, &contract.spec.merkle_root)?;
            }
            if seen_validators.insert(receipt.body.validator.clone()) {
                validated.push(receipt.clone());
            }
        }
        Ok(validated)
    }

    fn select_consensus_storage_receipts(
        &self,
        receipts: &[SignedStorageProofReceipt],
    ) -> Result<Vec<SignedStorageProofReceipt>> {
        let mut clusters: BTreeMap<String, Vec<SignedStorageProofReceipt>> = BTreeMap::new();
        for receipt in receipts {
            let outcome_key = storage_proof_outcome_key(receipt)?;
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
            bail!("storage proof batch is missing validated receipts");
        };
        if tied {
            bail!("storage proof receipts do not reach a unique consensus outcome");
        }
        let winning_cluster = clusters.remove(&best_key).unwrap_or_default();
        if winning_cluster.len() * 2 <= receipts.len() {
            bail!("storage proof receipts do not reach majority consensus");
        }
        Ok(winning_cluster)
    }

    fn apply_heartbeat_observations(
        &mut self,
        observations: &[SignedHeartbeatObservation],
        proposed_at: DateTime<Utc>,
    ) -> Result<BTreeMap<(String, String), Vec<SignedHeartbeatObservation>>> {
        let mut grouped = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for observation in observations {
            verify_heartbeat_observation(observation)?;
            if observation.body.chain_id != self.chain_id {
                bail!("heartbeat observation is for a different chain");
            }
            let monitor = self
                .monitors
                .get(&observation.body.monitor_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown monitor {}", observation.body.monitor_id))?;
            let heartbeat = monitor.spec.heartbeat_config().ok_or_else(|| {
                anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id)
            })?;
            let expected_slot_key =
                schedule_current_slot_start(&monitor.spec.schedule, observation.body.observed_at)?
                    .to_rfc3339();
            if observation.body.slot_key != expected_slot_key {
                bail!("heartbeat observation slot_key mismatch");
            }
            validate_monitor_heartbeat_observation(&monitor, observation)?;
            if monitor.paused {
                bail!("paused monitors do not accept heartbeat observations");
            }
            if !seen.insert(observation.id.clone()) {
                continue;
            }

            self.ensure_slot_budget_reserved(
                &monitor.monitor_id,
                &observation.body.slot_key,
                proposed_at,
            )?;
            self.charge_monitor_budget(&monitor.monitor_id, MONITOR_PING_INGRESS_FEE);
            self.accounts
                .entry(observation.body.observed_by.clone())
                .or_default()
                .balance += MONITOR_PING_INGRESS_FEE;

            let slot_started_at =
                schedule_current_slot_start(&monitor.spec.schedule, observation.body.observed_at)?;
            let deadline_at = slot_deadline(slot_started_at, monitor.spec.grace_secs);
            let slot_record = self
                .monitor_slot_history
                .entry(monitor.monitor_id.clone())
                .or_default()
                .entry(observation.body.slot_key.clone())
                .or_insert_with(|| MonitorSlotRecord {
                    monitor_id: monitor.monitor_id.clone(),
                    slot_key: observation.body.slot_key.clone(),
                    slot_started_at,
                    deadline_at,
                    status: if monitor.paused {
                        MonitorSlotStatus::Paused
                    } else {
                        MonitorSlotStatus::Pending
                    },
                    finalized_at: proposed_at,
                    observation_ids: Vec::new(),
                    confirmation_success: None,
                });
            if !slot_record.observation_ids.contains(&observation.id) {
                slot_record.observation_ids.push(observation.id.clone());
            }
            slot_record.finalized_at = proposed_at;

            match observation.body.signal {
                HeartbeatSignal::Start => {
                    if let Some(run_timeout_secs) = signal_run_timeout_secs(heartbeat.signal_policy)
                    {
                        let extended = observation.body.observed_at
                            + chrono::Duration::seconds(run_timeout_secs as i64);
                        if extended > slot_record.deadline_at {
                            slot_record.deadline_at = extended;
                        }
                    }
                    slot_record.status = MonitorSlotStatus::Running;
                    if let Some(current) = self.monitors.get_mut(&monitor.monitor_id) {
                        current.status = MonitorStatus::Running;
                        current.updated_at = proposed_at;
                        current.last_observation_at = Some(observation.body.observed_at);
                        current.next_slot_hint = schedule_next_slot_start(
                            &current.spec.schedule,
                            slot_record.slot_started_at,
                        )
                        .ok()
                        .map(|value| value.to_rfc3339());
                    }
                }
                HeartbeatSignal::Success => {
                    let was_late = matches!(
                        slot_record.status,
                        MonitorSlotStatus::MissedUnconfirmed
                            | MonitorSlotStatus::MissedServiceReachable
                            | MonitorSlotStatus::DownConfirmed
                            | MonitorSlotStatus::FailedExplicit
                    ) || observation.body.observed_at > slot_record.deadline_at;
                    slot_record.status = if was_late {
                        MonitorSlotStatus::RecoveredLate
                    } else {
                        MonitorSlotStatus::Ok
                    };
                    if let Some(current) = self.monitors.get_mut(&monitor.monitor_id) {
                        current.status = monitor_ready_status(
                            current.paused,
                            &current.spec,
                            current.budget_balance,
                        );
                        current.updated_at = proposed_at;
                        current.last_observation_at = Some(observation.body.observed_at);
                        current.next_slot_hint = schedule_next_slot_start(
                            &current.spec.schedule,
                            slot_record.slot_started_at,
                        )
                        .ok()
                        .map(|value| value.to_rfc3339());
                    }
                    if was_late {
                        self.add_alert_fact(
                            &monitor.monitor_id,
                            &observation.body.slot_key,
                            MonitorSlotStatus::RecoveredLate,
                            proposed_at,
                            monitor.spec.notification_policy_id.clone(),
                        )?;
                    }
                }
                HeartbeatSignal::Fail => {
                    slot_record.status = MonitorSlotStatus::FailedExplicit;
                    if let Some(current) = self.monitors.get_mut(&monitor.monitor_id) {
                        current.status = MonitorStatus::Down;
                        current.updated_at = proposed_at;
                        current.last_observation_at = Some(observation.body.observed_at);
                        current.next_slot_hint = schedule_next_slot_start(
                            &current.spec.schedule,
                            slot_record.slot_started_at,
                        )
                        .ok()
                        .map(|value| value.to_rfc3339());
                    }
                    self.add_alert_fact(
                        &monitor.monitor_id,
                        &observation.body.slot_key,
                        MonitorSlotStatus::FailedExplicit,
                        proposed_at,
                        monitor.spec.notification_policy_id.clone(),
                    )?;
                }
            }

            grouped
                .entry((
                    monitor.monitor_id.clone(),
                    observation.body.slot_key.clone(),
                ))
                .or_insert_with(Vec::new)
                .push(observation.clone());
        }
        Ok(grouped)
    }

    fn apply_monitor_evaluations(
        &mut self,
        evaluations: &[MonitorEvaluation],
        observations_by_slot: &BTreeMap<(String, String), Vec<SignedHeartbeatObservation>>,
        monitor_browser_batches: &BTreeMap<(String, String), MonitorBrowserBatch>,
        confirmation_batches: &BTreeMap<(String, String), MonitorConfirmationBatch>,
        proposed_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        for evaluation in evaluations {
            if !seen.insert((
                evaluation.monitor_id.clone(),
                evaluation.slot_key.clone(),
                evaluation.kind.clone(),
            )) {
                continue;
            }
            let monitor = self
                .monitors
                .get(&evaluation.monitor_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown monitor {}", evaluation.monitor_id))?;
            let slot_started_at = DateTime::parse_from_rfc3339(&evaluation.slot_key)
                .map_err(|error| anyhow!("invalid slot_key: {error}"))?
                .with_timezone(&Utc);
            let deadline_at = self
                .monitor_slot_history
                .get(&monitor.monitor_id)
                .and_then(|slots| slots.get(&evaluation.slot_key))
                .map(|slot| slot.deadline_at)
                .unwrap_or_else(|| slot_deadline(slot_started_at, monitor.spec.grace_secs));
            let heartbeat = monitor.spec.heartbeat_config();

            match evaluation.kind {
                MonitorEvaluationKind::SlotSatisfied => {
                    if heartbeat.is_none() {
                        bail!("slot satisfied evaluations are only valid for heartbeat monitors");
                    }
                    let has_success = observations_by_slot
                        .get(&(evaluation.monitor_id.clone(), evaluation.slot_key.clone()))
                        .map(|items| {
                            items
                                .iter()
                                .any(|item| item.body.signal == HeartbeatSignal::Success)
                        })
                        .unwrap_or(false);
                    if !has_success {
                        bail!("slot satisfied evaluation requires a success observation");
                    }
                    {
                        let slot_record = self
                            .monitor_slot_history
                            .entry(monitor.monitor_id.clone())
                            .or_default()
                            .entry(evaluation.slot_key.clone())
                            .or_insert_with(|| MonitorSlotRecord {
                                monitor_id: monitor.monitor_id.clone(),
                                slot_key: evaluation.slot_key.clone(),
                                slot_started_at,
                                deadline_at,
                                status: MonitorSlotStatus::Pending,
                                finalized_at: proposed_at,
                                observation_ids: Vec::new(),
                                confirmation_success: None,
                            });
                        slot_record.finalized_at = proposed_at;
                        slot_record.status = MonitorSlotStatus::Ok;
                    }
                    if let Some(current) = self.monitors.get_mut(&evaluation.monitor_id) {
                        current.status = monitor_ready_status(
                            current.paused,
                            &current.spec,
                            current.budget_balance,
                        );
                        current.updated_at = proposed_at;
                        current.next_slot_hint =
                            schedule_next_slot_start(&current.spec.schedule, slot_started_at)
                                .ok()
                                .map(|value| value.to_rfc3339());
                    }
                }
                MonitorEvaluationKind::SlotMissed => {
                    if proposed_at <= deadline_at {
                        bail!("slot missed evaluation is before the slot deadline");
                    }
                    let mut status = MonitorSlotStatus::MissedUnconfirmed;
                    let mut confirmation_success = None;
                    match heartbeat {
                        Some(heartbeat) => {
                            let has_success = observations_by_slot
                                .get(&(evaluation.monitor_id.clone(), evaluation.slot_key.clone()))
                                .map(|items| {
                                    items
                                        .iter()
                                        .any(|item| item.body.signal == HeartbeatSignal::Success)
                                })
                                .unwrap_or(false);
                            if has_success {
                                bail!(
                                    "slot missed evaluation cannot coexist with a success observation"
                                );
                            }
                            if let Some(batch) = confirmation_batches
                                .get(&(evaluation.monitor_id.clone(), evaluation.slot_key.clone()))
                            {
                                let (consensus_success, rewarded) =
                                    self.apply_confirmation_batch(&monitor, batch)?;
                                confirmation_success = Some(consensus_success);
                                status = if consensus_success {
                                    MonitorSlotStatus::MissedServiceReachable
                                } else {
                                    MonitorSlotStatus::DownConfirmed
                                };
                                let charge = confirmation_probe_cost(batch)?;
                                self.distribute_monitor_confirmation_rewards(
                                    &evaluation.monitor_id,
                                    charge,
                                    &rewarded,
                                );
                            } else if matches!(
                                heartbeat.miss_policy,
                                crate::protocol::MissPolicy::ConfirmWithValidators { .. }
                                    | crate::protocol::MissPolicy::ConfirmWithDelegatedAgents { .. }
                            ) && heartbeat.confirmation_probe.is_some()
                            {
                                status = MonitorSlotStatus::MissedUnconfirmed;
                            }
                        }
                        None => {
                            if monitor_browser_batches.contains_key(&(
                                evaluation.monitor_id.clone(),
                                evaluation.slot_key.clone(),
                            )) {
                                bail!("browser monitor slot cannot be both missed and executed");
                            }
                        }
                    }
                    {
                        let slot_record = self
                            .monitor_slot_history
                            .entry(monitor.monitor_id.clone())
                            .or_default()
                            .entry(evaluation.slot_key.clone())
                            .or_insert_with(|| MonitorSlotRecord {
                                monitor_id: monitor.monitor_id.clone(),
                                slot_key: evaluation.slot_key.clone(),
                                slot_started_at,
                                deadline_at,
                                status: MonitorSlotStatus::Pending,
                                finalized_at: proposed_at,
                                observation_ids: Vec::new(),
                                confirmation_success: None,
                            });
                        slot_record.finalized_at = proposed_at;
                        slot_record.confirmation_success = confirmation_success;
                        slot_record.status = status.clone();
                    }
                    if let Some(current) = self.monitors.get_mut(&evaluation.monitor_id) {
                        current.status = if current.paused {
                            MonitorStatus::Paused
                        } else if current.budget_balance
                            < monitor_minimum_slot_balance(&current.spec).unwrap_or(u64::MAX)
                        {
                            MonitorStatus::InsufficientFunds
                        } else {
                            MonitorStatus::Late
                        };
                        if matches!(status, MonitorSlotStatus::DownConfirmed) {
                            current.status = MonitorStatus::Down;
                        }
                        current.updated_at = proposed_at;
                        current.next_slot_hint =
                            schedule_next_slot_start(&current.spec.schedule, slot_started_at)
                                .ok()
                                .map(|value| value.to_rfc3339());
                    }
                    self.add_alert_fact(
                        &evaluation.monitor_id,
                        &evaluation.slot_key,
                        status,
                        proposed_at,
                        monitor.spec.notification_policy_id.clone(),
                    )?;
                }
                MonitorEvaluationKind::InsufficientFunds => {
                    if let Some(current) = self.monitors.get_mut(&evaluation.monitor_id) {
                        current.status = MonitorStatus::InsufficientFunds;
                        current.updated_at = proposed_at;
                        current.next_slot_hint =
                            schedule_next_slot_start(&current.spec.schedule, slot_started_at)
                                .ok()
                                .map(|value| value.to_rfc3339());
                    }
                    {
                        let slot_record = self
                            .monitor_slot_history
                            .entry(monitor.monitor_id.clone())
                            .or_default()
                            .entry(evaluation.slot_key.clone())
                            .or_insert_with(|| MonitorSlotRecord {
                                monitor_id: monitor.monitor_id.clone(),
                                slot_key: evaluation.slot_key.clone(),
                                slot_started_at,
                                deadline_at,
                                status: MonitorSlotStatus::Pending,
                                finalized_at: proposed_at,
                                observation_ids: Vec::new(),
                                confirmation_success: None,
                            });
                        slot_record.finalized_at = proposed_at;
                        slot_record.status = MonitorSlotStatus::InsufficientFunds;
                    }
                    self.add_alert_fact(
                        &evaluation.monitor_id,
                        &evaluation.slot_key,
                        MonitorSlotStatus::InsufficientFunds,
                        proposed_at,
                        monitor.spec.notification_policy_id.clone(),
                    )?;
                }
                MonitorEvaluationKind::Recovered => {
                    if heartbeat.is_none() {
                        bail!("recovered evaluations are only valid for heartbeat monitors");
                    }
                    let has_success = observations_by_slot
                        .get(&(evaluation.monitor_id.clone(), evaluation.slot_key.clone()))
                        .map(|items| {
                            items
                                .iter()
                                .any(|item| item.body.signal == HeartbeatSignal::Success)
                        })
                        .unwrap_or(false);
                    if !has_success {
                        bail!("recovered evaluation requires a success observation");
                    }
                    {
                        let slot_record = self
                            .monitor_slot_history
                            .entry(monitor.monitor_id.clone())
                            .or_default()
                            .entry(evaluation.slot_key.clone())
                            .or_insert_with(|| MonitorSlotRecord {
                                monitor_id: monitor.monitor_id.clone(),
                                slot_key: evaluation.slot_key.clone(),
                                slot_started_at,
                                deadline_at,
                                status: MonitorSlotStatus::Pending,
                                finalized_at: proposed_at,
                                observation_ids: Vec::new(),
                                confirmation_success: None,
                            });
                        slot_record.finalized_at = proposed_at;
                        slot_record.status = MonitorSlotStatus::RecoveredLate;
                    }
                    if let Some(current) = self.monitors.get_mut(&evaluation.monitor_id) {
                        current.status = monitor_ready_status(
                            current.paused,
                            &current.spec,
                            current.budget_balance,
                        );
                        current.updated_at = proposed_at;
                        current.next_slot_hint =
                            schedule_next_slot_start(&current.spec.schedule, slot_started_at)
                                .ok()
                                .map(|value| value.to_rfc3339());
                    }
                    self.add_alert_fact(
                        &evaluation.monitor_id,
                        &evaluation.slot_key,
                        MonitorSlotStatus::RecoveredLate,
                        proposed_at,
                        monitor.spec.notification_policy_id.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn apply_monitor_browser_batches(
        &mut self,
        batches: &[MonitorBrowserBatch],
        proposed_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        for batch in batches {
            if !seen.insert((batch.monitor_id.clone(), batch.slot_key.clone())) {
                continue;
            }
            let monitor = self
                .monitors
                .get(&batch.monitor_id)
                .cloned()
                .ok_or_else(|| anyhow!("unknown monitor {}", batch.monitor_id))?;
            let package = monitor.spec.browser_package().ok_or_else(|| {
                anyhow!("monitor {} is not a browser monitor", monitor.monitor_id)
            })?;
            let cost = monitor_browser_slot_cost(package)?;
            if monitor.budget_balance < cost {
                bail!(
                    "browser monitor {} requires at least {} budget for slot {}",
                    monitor.monitor_id,
                    cost,
                    batch.slot_key
                );
            }

            let slot_started_at = DateTime::parse_from_rfc3339(&batch.slot_key)
                .map_err(|error| anyhow!("invalid slot_key: {error}"))?
                .with_timezone(&Utc);
            let deadline_at = slot_deadline(slot_started_at, monitor.spec.grace_secs);
            let unique_valid_receipts =
                self.validate_monitor_browser_receipts(&monitor, &batch.slot_key, &batch.receipts)?;
            let rewarded_receipts =
                self.select_consensus_browser_receipts(&unique_valid_receipts)?;

            let reward_per_validator = cost / rewarded_receipts.len() as u64;
            let distributed = reward_per_validator * rewarded_receipts.len() as u64;
            let remainder = cost - distributed;
            self.charge_monitor_budget(&monitor.monitor_id, cost);
            for receipt in &rewarded_receipts {
                self.accounts
                    .entry(receipt.body.executor.clone())
                    .or_default()
                    .balance += reward_per_validator;
            }
            self.accounts
                .entry(self.treasury.clone())
                .or_default()
                .balance += remainder;

            let consensus_success = rewarded_receipts
                .first()
                .map(|receipt| receipt.body.success)
                .unwrap_or(false);
            let status = if consensus_success {
                MonitorSlotStatus::Ok
            } else {
                MonitorSlotStatus::DownConfirmed
            };

            {
                let slot_record = self
                    .monitor_slot_history
                    .entry(monitor.monitor_id.clone())
                    .or_default()
                    .entry(batch.slot_key.clone())
                    .or_insert_with(|| MonitorSlotRecord {
                        monitor_id: monitor.monitor_id.clone(),
                        slot_key: batch.slot_key.clone(),
                        slot_started_at,
                        deadline_at,
                        status: MonitorSlotStatus::Pending,
                        finalized_at: proposed_at,
                        observation_ids: Vec::new(),
                        confirmation_success: None,
                    });
                slot_record.finalized_at = proposed_at;
                slot_record.status = status.clone();
                slot_record.confirmation_success = Some(consensus_success);
            }
            if let Some(current) = self.monitors.get_mut(&monitor.monitor_id) {
                current.status = if current.paused {
                    MonitorStatus::Paused
                } else if consensus_success {
                    monitor_ready_status(current.paused, &current.spec, current.budget_balance)
                } else {
                    MonitorStatus::Down
                };
                current.updated_at = proposed_at;
                current.next_slot_hint =
                    schedule_next_slot_start(&current.spec.schedule, slot_started_at)
                        .ok()
                        .map(|value| value.to_rfc3339());
            }
            if !consensus_success {
                self.add_alert_fact(
                    &monitor.monitor_id,
                    &batch.slot_key,
                    MonitorSlotStatus::DownConfirmed,
                    proposed_at,
                    monitor.spec.notification_policy_id.clone(),
                )?;
            }
        }
        Ok(())
    }

    fn validate_monitor_browser_receipts(
        &self,
        monitor: &MonitorRecord,
        slot_key: &str,
        receipts: &[SignedBrowserReceipt],
    ) -> Result<Vec<SignedBrowserReceipt>> {
        let package = monitor
            .spec
            .browser_package()
            .ok_or_else(|| anyhow!("monitor {} is not a browser monitor", monitor.monitor_id))?;
        let synthetic_tx_hash = monitor_browser_tx_hash(&monitor.monitor_id, slot_key)?;
        let synthetic_request_id = monitor_browser_request_id(&monitor.monitor_id, slot_key);
        let package_hash = crate::browser::browser_package_hash(package)?;
        let runtime_hash = crate::browser::browser_runtime_hash(&package.runtime)?;
        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in receipts {
            verify_browser_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("browser monitor receipt is for a different chain");
            }
            if receipt.body.tx_hash != synthetic_tx_hash {
                bail!("browser monitor receipt tx_hash mismatch");
            }
            if receipt.body.request_id != synthetic_request_id {
                bail!("browser monitor receipt request_id mismatch");
            }
            if receipt.body.monitor_id.as_deref() != Some(monitor.monitor_id.as_str()) {
                bail!("browser monitor receipt monitor_id mismatch");
            }
            if receipt.body.slot_key.as_deref() != Some(slot_key) {
                bail!("browser monitor receipt slot_key mismatch");
            }
            if receipt.body.package_hash != package_hash {
                bail!("browser monitor receipt package_hash mismatch");
            }
            if receipt.body.runtime_hash != runtime_hash {
                bail!("browser monitor receipt runtime_hash mismatch");
            }
            if !self.validators.contains(&receipt.body.executor) {
                bail!("browser monitor receipt signer is not a validator");
            }
            if seen.insert(receipt.body.executor.clone()) {
                validated.push(receipt.clone());
            }
        }
        if validated.len() < self.min_health_receipts {
            bail!(
                "browser monitor {}:{} requires at least {} validator receipts",
                monitor.monitor_id,
                slot_key,
                self.min_health_receipts
            );
        }
        Ok(validated)
    }

    fn apply_confirmation_batch(
        &self,
        monitor: &MonitorRecord,
        batch: &MonitorConfirmationBatch,
    ) -> Result<(bool, Vec<SignedHealthReceipt>)> {
        if batch.monitor_id != monitor.monitor_id {
            bail!("confirmation batch monitor_id mismatch");
        }
        let heartbeat = monitor
            .spec
            .heartbeat_config()
            .ok_or_else(|| anyhow!("monitor {} is not a heartbeat monitor", monitor.monitor_id))?;
        let spec = heartbeat
            .confirmation_probe
            .cloned()
            .ok_or_else(|| anyhow!("monitor is missing confirmation_probe"))?;
        let synthetic_tx_hash = monitor_confirmation_tx_hash(&monitor.monitor_id, &batch.slot_key)?;
        let synthetic_request_id =
            monitor_confirmation_request_id(&monitor.monitor_id, &batch.slot_key);
        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for receipt in &batch.validator_receipts {
            verify_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("confirmation receipt is for a different chain");
            }
            if receipt.body.tx_hash != synthetic_tx_hash {
                bail!("confirmation receipt tx_hash mismatch");
            }
            if receipt.body.request_id != synthetic_request_id {
                bail!("confirmation receipt request_id mismatch");
            }
            if !self.validators.contains(&receipt.body.executor) {
                bail!("confirmation receipt signer is not a validator");
            }
            if seen.insert(receipt.body.executor.clone()) {
                validated.push(receipt.clone());
            }
        }
        let required_receipts =
            required_monitor_confirmation_receipts(heartbeat.miss_policy, self.validators.len());
        if validated.len() < required_receipts {
            bail!(
                "confirmation batch for {}:{} requires at least {} validator receipts",
                monitor.monitor_id,
                batch.slot_key,
                required_receipts
            );
        }
        let validator_executors = validated
            .iter()
            .map(|receipt| receipt.body.executor.clone())
            .collect::<BTreeSet<_>>();
        let mut delegated_agents = BTreeSet::new();
        let mut delegated_leases = BTreeSet::new();
        let mut delegated_regions = BTreeSet::new();
        let mut delegated_count = 0usize;
        for receipt in &batch.delegated_receipts {
            verify_delegated_probe_receipt(receipt)?;
            if receipt.body.chain_id != self.chain_id {
                bail!("delegated confirmation receipt is for a different chain");
            }
            if receipt.body.monitor_id != monitor.monitor_id
                || receipt.body.slot_key != batch.slot_key
            {
                bail!("delegated confirmation receipt slot mismatch");
            }
            if !self.validators.contains(&receipt.body.parent_validator) {
                bail!("delegated confirmation parent validator is not in the validator set");
            }
            if !validator_executors.contains(&receipt.body.parent_validator) {
                bail!("delegated confirmation parent validator is missing validator attestation");
            }
            if receipt.body.request_id.as_deref() != Some(synthetic_request_id.as_str()) {
                bail!("delegated confirmation receipt request_id mismatch");
            }
            let lease_id = receipt
                .body
                .lease_id
                .as_deref()
                .map(str::trim)
                .filter(|lease_id| !lease_id.is_empty())
                .ok_or_else(|| {
                    anyhow!("delegated confirmation receipt lease_id cannot be empty")
                })?;
            if !delegated_agents.insert(receipt.body.agent_public_key.clone()) {
                bail!("delegated confirmation receipt agent_public_key is duplicated");
            }
            if !delegated_leases.insert(lease_id.to_string()) {
                bail!("delegated confirmation receipt lease_id is duplicated");
            }
            if let Some(region) = receipt.body.region.as_deref().map(str::trim)
                && !region.is_empty()
            {
                delegated_regions.insert(region.to_string());
            }
            delegated_count += 1;
        }
        if let crate::protocol::MissPolicy::ConfirmWithDelegatedAgents {
            require_region_diversity,
            ..
        } = heartbeat.miss_policy
        {
            let required_delegated =
                required_delegated_probe_receipts(heartbeat.miss_policy, required_receipts);
            if delegated_count < required_delegated {
                bail!(
                    "confirmation batch for {}:{} requires at least {} delegated receipts",
                    monitor.monitor_id,
                    batch.slot_key,
                    required_delegated
                );
            }
            if delegated_regions.len() < *require_region_diversity {
                bail!(
                    "confirmation batch for {}:{} requires at least {} delegated regions",
                    monitor.monitor_id,
                    batch.slot_key,
                    require_region_diversity
                );
            }
        }
        let _ = health_check_cost(&spec)?;
        let rewarded = self.select_consensus_health_receipts(&validated)?;
        let consensus_success = rewarded
            .first()
            .map(|receipt| receipt.body.success)
            .unwrap_or(false);
        Ok((consensus_success, rewarded))
    }

    fn ensure_slot_budget_reserved(
        &mut self,
        monitor_id: &str,
        slot_key: &str,
        proposed_at: DateTime<Utc>,
    ) -> Result<()> {
        let slot_exists = self
            .monitor_slot_history
            .get(monitor_id)
            .and_then(|slots| slots.get(slot_key))
            .is_some();
        if slot_exists {
            return Ok(());
        }
        let spec = self
            .monitors
            .get(monitor_id)
            .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?
            .spec
            .clone();
        if !spec.is_heartbeat() {
            bail!("slot reservation is only supported for heartbeat monitors");
        }
        self.charge_monitor_budget(monitor_id, MONITOR_SLOT_RESERVATION_FEE);
        let current = self
            .monitors
            .get_mut(monitor_id)
            .ok_or_else(|| anyhow!("unknown monitor {monitor_id}"))?;
        if current.budget_balance < monitor_minimum_slot_balance(&spec).unwrap_or(u64::MAX) {
            current.status = MonitorStatus::InsufficientFunds;
            current.updated_at = proposed_at;
        }
        Ok(())
    }

    fn charge_monitor_budget(&mut self, monitor_id: &str, amount: u64) -> u64 {
        let Some(monitor) = self.monitors.get_mut(monitor_id) else {
            return 0;
        };
        let charged = monitor.budget_balance.min(amount);
        monitor.budget_balance -= charged;
        charged
    }

    fn distribute_monitor_confirmation_rewards(
        &mut self,
        monitor_id: &str,
        amount: u64,
        rewarded: &[SignedHealthReceipt],
    ) {
        let charged = self.charge_monitor_budget(monitor_id, amount);
        if charged == 0 || rewarded.is_empty() {
            return;
        }
        let reward_per_validator = charged / rewarded.len() as u64;
        let distributed = reward_per_validator * rewarded.len() as u64;
        let remainder = charged.saturating_sub(distributed);
        for receipt in rewarded {
            self.accounts
                .entry(receipt.body.executor.clone())
                .or_default()
                .balance += reward_per_validator;
        }
        self.accounts
            .entry(self.treasury.clone())
            .or_default()
            .balance += remainder;
    }

    fn add_alert_fact(
        &mut self,
        monitor_id: &str,
        slot_key: &str,
        status: MonitorSlotStatus,
        created_at: DateTime<Utc>,
        notification_policy_id: Option<String>,
    ) -> Result<()> {
        let id = compute_hash(&(
            monitor_id.to_string(),
            slot_key.to_string(),
            status.clone(),
            created_at,
        ))?;
        self.alert_facts.entry(id.clone()).or_insert(AlertFact {
            id,
            monitor_id: monitor_id.to_string(),
            slot_key: slot_key.to_string(),
            status,
            created_at,
            notification_policy_id,
        });
        self.charge_monitor_budget(monitor_id, MONITOR_ALERT_DELIVERY_FEE);
        Ok(())
    }
}

fn monitor_ready_status(
    paused: bool,
    spec: &crate::protocol::MonitorSpec,
    budget_balance: u64,
) -> MonitorStatus {
    if paused {
        MonitorStatus::Paused
    } else if budget_balance < monitor_minimum_slot_balance(spec).unwrap_or(u64::MAX) {
        MonitorStatus::InsufficientFunds
    } else {
        MonitorStatus::Up
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
        bail!("heartbeat observation uses a disabled signal type");
    }
    match (heartbeat.ping_auth, observation.body.auth_mode) {
        (HeartbeatAuth::SecretUrl { .. }, HeartbeatAuthMode::SecretUrl) => {}
        (HeartbeatAuth::Dual { .. }, HeartbeatAuthMode::SecretUrl) => {}
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
            let payload = canonical_heartbeat_client_message(
                &observation.body.monitor_id,
                observation.body.signal,
                client_timestamp,
                client_nonce,
                observation.body.body_sha256.as_deref(),
            )?;
            verify_signed_message(public_key, &payload, client_signature)?;
        }
        _ => bail!("heartbeat auth mode does not match the monitor"),
    }
    Ok(())
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

fn signal_run_timeout_secs(policy: &SignalPolicy) -> Option<u64> {
    match policy {
        SignalPolicy::SuccessOnly => None,
        SignalPolicy::StartAndSuccess { run_timeout_secs }
        | SignalPolicy::StartSuccessFail { run_timeout_secs } => Some(*run_timeout_secs),
    }
}

#[derive(Serialize)]
struct ConsensusAssertionView<'a> {
    assertion: &'a crate::protocol::ResponseAssertion,
    passed: bool,
}

#[derive(Serialize)]
struct ConsensusReceiptView<'a> {
    success: bool,
    response_status: Option<u16>,
    error: Option<String>,
    assertion_results: Vec<ConsensusAssertionView<'a>>,
}

#[derive(Serialize)]
struct BrowserConsensusReceiptView<'a> {
    success: bool,
    failed_step_index: Option<usize>,
    outcome_class: &'a BrowserOutcomeClass,
    final_url: Option<&'a str>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ComputeConsensusReceiptView<'a> {
    success: bool,
    job_hash: &'a str,
    reduced_output: Option<&'a serde_json::Value>,
    shard_outputs: Vec<ComputeConsensusShardOutputView<'a>>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ComputeConsensusShardOutputView<'a> {
    shard_id: &'a str,
    success: bool,
    output: Option<&'a serde_json::Value>,
    error: Option<String>,
    artifacts: Vec<ComputeConsensusArtifactView<'a>>,
}

#[derive(Serialize)]
struct ComputeConsensusArtifactView<'a> {
    path: &'a str,
    size_bytes: u64,
    sha256: &'a str,
    content_type: Option<&'a str>,
}

#[derive(Serialize)]
struct StorageConsensusReceiptView<'a> {
    contract_id: &'a str,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    bytes_stored: u64,
    merkle_root: &'a str,
    challenge_seed: &'a str,
    success: bool,
    error: Option<String>,
    samples: &'a [crate::protocol::StorageProofSample],
}

fn health_outcome_key(receipt: &SignedHealthReceipt) -> Result<String> {
    let assertion_results = receipt
        .body
        .assertion_results
        .iter()
        .map(|result| ConsensusAssertionView {
            assertion: &result.assertion,
            passed: result.passed,
        })
        .collect();
    compute_hash(&ConsensusReceiptView {
        success: receipt.body.success,
        response_status: receipt.body.response_status,
        error: normalize_receipt_error(receipt.body.error.as_deref()),
        assertion_results,
    })
}

fn browser_outcome_key(receipt: &SignedBrowserReceipt) -> Result<String> {
    compute_hash(&BrowserConsensusReceiptView {
        success: receipt.body.success,
        failed_step_index: receipt.body.failed_step_index,
        outcome_class: &receipt.body.outcome_class,
        final_url: receipt.body.final_url.as_deref(),
        error: normalize_receipt_error(receipt.body.error.as_deref()),
    })
}

fn compute_outcome_key(receipt: &SignedComputeReceipt) -> Result<String> {
    let shard_outputs = receipt
        .body
        .shard_outputs
        .iter()
        .map(|output| ComputeConsensusShardOutputView {
            shard_id: &output.shard_id,
            success: output.success,
            output: output.output.as_ref(),
            error: normalize_receipt_error(output.error.as_deref()),
            artifacts: output
                .artifacts
                .iter()
                .map(|artifact| ComputeConsensusArtifactView {
                    path: &artifact.path,
                    size_bytes: artifact.size_bytes,
                    sha256: &artifact.sha256,
                    content_type: artifact.content_type.as_deref(),
                })
                .collect(),
        })
        .collect();
    compute_hash(&ComputeConsensusReceiptView {
        success: receipt.body.success,
        job_hash: &receipt.body.job_hash,
        reduced_output: receipt.body.reduced_output.as_ref(),
        shard_outputs,
        error: normalize_receipt_error(receipt.body.error.as_deref()),
    })
}

fn storage_proof_outcome_key(receipt: &SignedStorageProofReceipt) -> Result<String> {
    compute_hash(&StorageConsensusReceiptView {
        contract_id: &receipt.body.contract_id,
        window_start: receipt.body.window_start,
        window_end: receipt.body.window_end,
        bytes_stored: receipt.body.bytes_stored,
        merkle_root: &receipt.body.merkle_root,
        challenge_seed: &receipt.body.challenge_seed,
        success: receipt.body.success,
        error: normalize_receipt_error(receipt.body.error.as_deref()),
        samples: &receipt.body.samples,
    })
}

fn normalize_receipt_error(error: Option<&str>) -> Option<String> {
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

fn monitor_confirmation_tx_hash(monitor_id: &str, slot_key: &str) -> Result<String> {
    compute_hash(&(monitor_id.to_string(), slot_key.to_string(), "confirmation"))
}

fn monitor_confirmation_request_id(monitor_id: &str, slot_key: &str) -> String {
    format!("monitor-confirmation:{monitor_id}:{slot_key}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        browser::{
            BrowserArtifactPolicy, BrowserEngine, BrowserJourneyPackage, BrowserJourneySpec,
            BrowserOutcomeClass, BrowserReceiptBody, BrowserRuntimeProfile, SessionCachePolicy,
            SignedBrowserReceipt,
        },
        compute::{
            ComputeIntegerOperation, ComputeReceiptBody, ComputeReducer, ComputeShardInput,
            ComputeShardOutput, ComputeShardSpec, ComputeWorkload,
        },
        protocol::{
            BlockApprovalBody, GenesisConfig, HEALTH_CHECK_BASE_COST, HealthCheckSpec,
            HealthHttpMethod, HeartbeatAuth, HeartbeatAuthMode, HeartbeatObservationBody,
            HeartbeatSignal, MICRO_CT, MICRO_DNS, MICRO_ST, MissPolicy, MonitorEvaluation,
            MonitorEvaluationKind, MonitorPathway, MonitorSpec, ProbeFanoutPolicy,
            STORAGE_BILLING_QUANTUM_BYTES, ScheduleSpec, SettlementAsset, SignalPolicy,
            SignedBlock, SignedBlockApproval, SignedDelegatedProbeReceipt, SignedHealthReceipt,
            SignedHeartbeatObservation, SignedStorageProofReceipt, SignedSwapQuote,
            SignedTransaction, StorageContractSpec, StorageMode, StorageProofBatch,
            StorageProofReceiptBody, StorageProofSample, SwapQuote, SwapSide, TransactionBody,
            TransactionKind, new_request_id, storage_challenge_indices, storage_challenge_seed,
            storage_chunk_count,
        },
        wallet::Wallet,
    };

    fn test_genesis(
        validators: &[Address],
        treasury: Address,
        requester: Address,
    ) -> GenesisConfig {
        let mut airdrops = BTreeMap::new();
        airdrops.insert(requester, HEALTH_CHECK_BASE_COST * 4);
        GenesisConfig {
            chain_id: "testnet".into(),
            treasury,
            validators: validators.to_vec(),
            chain_started_at: Utc::now(),
            block_time_secs: 3,
            min_health_receipts: 2,
            airdrops,
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        }
    }

    fn sample_compute_job_spec() -> ComputeJobSpec {
        ComputeJobSpec {
            request_id: "compute-job-1".into(),
            workload: ComputeWorkload::IntegerMap {
                operation: ComputeIntegerOperation::Sum,
            },
            shards: vec![
                ComputeShardSpec {
                    shard_id: "s1".into(),
                    input: ComputeShardInput::Integers { values: vec![1, 2] },
                },
                ComputeShardSpec {
                    shard_id: "s2".into(),
                    input: ComputeShardInput::Integers { values: vec![3, 4] },
                },
            ],
            reducer: ComputeReducer::Sum,
            max_runtime_secs: crate::compute::default_compute_runtime_secs(),
            replication: 1,
            sandbox: crate::compute::default_compute_sandbox_policy(),
            artifact_policy: crate::compute::default_compute_artifact_policy(),
        }
    }

    fn approval_for(wallet: &Wallet, block: &SignedBlock) -> SignedBlockApproval {
        wallet
            .sign_block_approval(SignedBlockApproval {
                id: String::new(),
                body: BlockApprovalBody {
                    chain_id: block.body.chain_id.clone(),
                    height: block.body.height,
                    view: block.body.view,
                    previous_hash: block.body.previous_hash.clone(),
                    block_hash: block.hash.clone(),
                    approver: String::new(),
                    approved_at: Utc::now(),
                },
                signature: String::new(),
            })
            .unwrap()
    }

    fn signed_sell_quote(
        quoting_validator: &Wallet,
        wallet: Address,
        token_amount: u64,
        expires_at: DateTime<Utc>,
    ) -> SignedSwapQuote {
        quoting_validator
            .sign_swap_quote(SignedSwapQuote {
                quote: SwapQuote {
                    chain_id: "testnet".into(),
                    quote_id: format!("quote-{}", new_request_id()),
                    wallet,
                    adapter: "fixed-usdc-demo".into(),
                    side: SwapSide::Sell,
                    settlement_asset: SettlementAsset::Usdc,
                    token_amount,
                    settlement_amount: token_amount,
                    settlement_decimals: 6,
                    expires_at,
                    notes: vec!["demo".into()],
                },
                quoted_by: String::new(),
                quoted_at: Utc::now(),
                signature: String::new(),
            })
            .unwrap()
    }

    fn sample_monitor_spec(monitor_id: &str, anchor_at: DateTime<Utc>) -> MonitorSpec {
        MonitorSpec {
            monitor_id: monitor_id.into(),
            slug: Some(monitor_id.into()),
            schedule: ScheduleSpec::Interval {
                every_secs: 60,
                anchor_at,
            },
            grace_secs: 10,
            pathway: MonitorPathway::Heartbeat {
                ping_auth: HeartbeatAuth::SecretUrl {
                    token_hash: crate::protocol::hash_secret_token("secret").unwrap(),
                },
                signal_policy: SignalPolicy::SuccessOnly,
                miss_policy: MissPolicy::ConfirmWithValidators {
                    fanout: ProbeFanoutPolicy::OnePerValidator,
                },
                confirmation_probe: Some(HealthCheckSpec {
                    request_id: format!("probe-{monitor_id}"),
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
                }),
            },
            notification_policy_id: Some("ops-webhook".into()),
            log_capture: crate::protocol::LogCapturePolicy::None,
            tags: BTreeMap::new(),
        }
    }

    fn sample_browser_package(owner: &str, approved_by: &str) -> BrowserJourneyPackage {
        BrowserJourneyPackage {
            package_id: "browser-package-1".into(),
            owner: owner.into(),
            manifest_version: 1,
            runtime: BrowserRuntimeProfile {
                engine: BrowserEngine::Chromium,
                engine_version: "playwright@1.54.0".into(),
                locale: "en-US".into(),
                timezone: "UTC".into(),
                viewport_width: 1440,
                viewport_height: 900,
                color_scheme: "light".into(),
                block_service_workers: true,
                cache_mode: Default::default(),
            },
            journey: BrowserJourneySpec {
                journey_id: "smoke-login".into(),
                entry_url: "https://example.com/login".into(),
                steps: vec![
                    crate::browser::BrowserStep::Navigate {
                        url: "https://example.com/login".into(),
                    },
                    crate::browser::BrowserStep::AssertUrlContains {
                        text: "/login".into(),
                    },
                ],
                max_runtime_secs: 30,
                per_step_timeout_ms: 5_000,
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
            approved_by: approved_by.into(),
            tags: BTreeMap::new(),
        }
    }

    fn sample_browser_monitor_spec(
        monitor_id: &str,
        anchor_at: DateTime<Utc>,
        owner: &str,
        approved_by: &str,
    ) -> MonitorSpec {
        MonitorSpec {
            monitor_id: monitor_id.into(),
            slug: Some(format!("{monitor_id}-browser")),
            schedule: ScheduleSpec::Interval {
                every_secs: 60,
                anchor_at,
            },
            grace_secs: 15,
            pathway: MonitorPathway::Browser {
                package: sample_browser_package(owner, approved_by),
            },
            notification_policy_id: Some("browser-webhook".into()),
            log_capture: crate::protocol::LogCapturePolicy::None,
            tags: BTreeMap::new(),
        }
    }

    #[test]
    fn health_check_cost_is_distributed_to_validators() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury.clone(),
            requester.address(),
        );
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::HealthCheck {
                        spec: HealthCheckSpec {
                            request_id: "job-1".into(),
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
                    },
                },
                signature: String::new(),
            })
            .unwrap();

        let receipt_a = validator_a
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-1".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 10,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let receipt_b = validator_b
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-1".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 12,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx],
                    health_batches: vec![BlockHealthBatch {
                        tx_hash: receipt_a.body.tx_hash.clone(),
                        receipts: vec![receipt_a.clone(), receipt_b.clone()],
                    }],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        state.apply_block(&block).unwrap();

        let requester_balance = state.account(&requester.address()).balance;
        assert_eq!(requester_balance, HEALTH_CHECK_BASE_COST * 3);

        let reward = HEALTH_CHECK_BASE_COST / 2;
        assert_eq!(state.account(&validator_b.address()).balance, reward);
        assert!(
            state
                .finalized_health_checks
                .contains_key(&receipt_a.body.tx_hash)
        );
        assert_eq!(state.height, 1);
    }

    #[test]
    fn compute_transfer_moves_compute_tokens_only() {
        let sender = Wallet::generate();
        let recipient = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let mut genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            sender.address(),
        );
        genesis
            .compute_airdrops
            .insert(sender.address(), MICRO_CT * 5);
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let tx = sender
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::ComputeTransfer {
                        to: recipient.address(),
                        amount: MICRO_CT * 2,
                    },
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        state.apply_block(&block).unwrap();

        assert_eq!(
            state.account(&sender.address()).compute_balance,
            MICRO_CT * 3
        );
        assert_eq!(
            state.account(&recipient.address()).compute_balance,
            MICRO_CT * 2
        );
        assert_eq!(
            state.account(&sender.address()).balance,
            HEALTH_CHECK_BASE_COST * 4
        );
        assert_eq!(state.account(&sender.address()).nonce, 1);
    }

    #[test]
    fn compute_job_spends_compute_tokens_and_rewards_validators() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let mut genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            requester.address(),
        );
        genesis
            .compute_airdrops
            .insert(requester.address(), MICRO_CT * 10);
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let spec = sample_compute_job_spec();
        let request_cost = state.compute_request_cost(&spec).unwrap();

        let tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::ComputeJob { spec: spec.clone() },
                },
                signature: String::new(),
            })
            .unwrap();

        let shard_outputs = vec![
            ComputeShardOutput {
                shard_id: "s1".into(),
                success: true,
                latency_ms: 5,
                output: Some(serde_json::json!({ "sum": 3, "count": 2 })),
                error: None,
                artifacts: Vec::new(),
                stdout_sample: None,
                stderr_sample: None,
            },
            ComputeShardOutput {
                shard_id: "s2".into(),
                success: true,
                latency_ms: 6,
                output: Some(serde_json::json!({ "sum": 7, "count": 2 })),
                error: None,
                artifacts: Vec::new(),
                stdout_sample: None,
                stderr_sample: None,
            },
        ];
        let reduced_output = serde_json::json!({ "sum": 10 });
        let job_hash = compute_job_hash(&spec).unwrap();
        let receipt_a = validator_a
            .sign_compute_receipt(SignedComputeReceipt {
                id: String::new(),
                body: ComputeReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: spec.request_id.clone(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    job_hash: job_hash.clone(),
                    assigned_agents: BTreeMap::new(),
                    shard_outputs: shard_outputs.clone(),
                    reduced_output: Some(reduced_output.clone()),
                    latency_ms: 11,
                    success: true,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let receipt_b = validator_b
            .sign_compute_receipt(SignedComputeReceipt {
                id: String::new(),
                body: ComputeReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: spec.request_id.clone(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    job_hash,
                    assigned_agents: BTreeMap::new(),
                    shard_outputs,
                    reduced_output: Some(reduced_output.clone()),
                    latency_ms: 12,
                    success: true,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx.clone()],
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: vec![BlockComputeBatch {
                        tx_hash: tx.hash.clone(),
                        receipts: vec![receipt_a.clone(), receipt_b.clone()],
                    }],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        state.apply_block(&block).unwrap();

        let reward = request_cost / 2;
        assert_eq!(
            state.account(&requester.address()).compute_balance,
            MICRO_CT * 10 - request_cost
        );
        assert_eq!(
            state.account(&validator_a.address()).compute_balance,
            reward
        );
        assert_eq!(
            state.account(&validator_b.address()).compute_balance,
            reward
        );
        let record = state.finalized_compute_jobs.get(&tx.hash).unwrap();
        assert_eq!(record.requester_cost, request_cost);
        assert_eq!(record.reduced_output, Some(reduced_output));
        assert!(state.finalized_compute_job_ids.contains(&tx.hash));
    }

    #[test]
    fn genesis_rejects_receipt_threshold_above_validator_count() {
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let requester = Wallet::generate();

        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: validator_a.address(),
            validators: vec![validator_a.address(), validator_b.address()],
            chain_started_at: Utc::now(),
            block_time_secs: 3,
            min_health_receipts: 3,
            airdrops: BTreeMap::from([(requester.address(), HEALTH_CHECK_BASE_COST)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };

        assert!(ChainState::from_genesis(&genesis).is_err());
    }

    #[test]
    fn receipt_request_id_must_match_health_check_request() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury.clone(),
            requester.address(),
        );
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::HealthCheck {
                        spec: HealthCheckSpec {
                            request_id: "expected-request".into(),
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
                    },
                },
                signature: String::new(),
            })
            .unwrap();

        let bad_receipt = validator_a
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "different-request".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 5,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let good_receipt = validator_b
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "expected-request".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 6,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx],
                    health_batches: vec![BlockHealthBatch {
                        tx_hash: bad_receipt.body.tx_hash.clone(),
                        receipts: vec![bad_receipt, good_receipt],
                    }],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        assert!(state.apply_block(&block).is_err());
    }

    #[test]
    fn health_check_rewards_only_majority_consensus_validators() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let validator_c = Wallet::generate();
        let treasury = validator_a.address();

        let mut genesis = test_genesis(
            &[
                validator_a.address(),
                validator_b.address(),
                validator_c.address(),
            ],
            treasury,
            requester.address(),
        );
        genesis.min_health_receipts = 3;
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::HealthCheck {
                        spec: HealthCheckSpec {
                            request_id: "job-majority".into(),
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
                    },
                },
                signature: String::new(),
            })
            .unwrap();

        let success_receipt_a = validator_a
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-majority".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 10,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let success_receipt_b = validator_b
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-majority".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 11,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let failure_receipt_c = validator_c
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-majority".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(503),
                    latency_ms: 12,
                    success: false,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx.clone()],
                    health_batches: vec![BlockHealthBatch {
                        tx_hash: tx.hash.clone(),
                        receipts: vec![
                            success_receipt_a.clone(),
                            success_receipt_b.clone(),
                            failure_receipt_c.clone(),
                        ],
                    }],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        state.apply_block(&block).unwrap();

        assert_eq!(
            state.account(&requester.address()).balance,
            HEALTH_CHECK_BASE_COST * 3
        );
        assert_eq!(
            state.account(&validator_a.address()).balance,
            HEALTH_CHECK_BASE_COST / 2
        );
        assert_eq!(
            state.account(&validator_b.address()).balance,
            HEALTH_CHECK_BASE_COST / 2
        );
        assert_eq!(state.account(&validator_c.address()).balance, 0);

        let finalized = state.finalized_health_checks.get(&tx.hash).unwrap();
        assert_eq!(finalized.receipts.len(), 3);
        assert_eq!(finalized.rewarded_receipts.len(), 2);
        assert!(finalized.consensus_success);
        assert_eq!(finalized.success_count, 2);
        assert_eq!(finalized.failure_count, 0);
        assert_eq!(finalized.divergent_count, 1);
    }

    #[test]
    fn split_receipts_fail_without_majority_consensus() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            requester.address(),
        );
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::HealthCheck {
                        spec: HealthCheckSpec {
                            request_id: "job-split".into(),
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
                    },
                },
                signature: String::new(),
            })
            .unwrap();

        let success_receipt = validator_a
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-split".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(200),
                    latency_ms: 10,
                    success: true,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();
        let failure_receipt = validator_b
            .sign_receipt(SignedHealthReceipt {
                id: String::new(),
                body: crate::protocol::HealthReceiptBody {
                    chain_id: "testnet".into(),
                    tx_hash: tx.hash.clone(),
                    request_id: "job-split".into(),
                    executor: String::new(),
                    observed_at: Utc::now(),
                    response_status: Some(503),
                    latency_ms: 11,
                    success: false,
                    assertion_results: Vec::new(),
                    response_headers: BTreeMap::new(),
                    response_body_sample: None,
                    error: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![tx.clone()],
                    health_batches: vec![BlockHealthBatch {
                        tx_hash: tx.hash.clone(),
                        receipts: vec![success_receipt, failure_receipt],
                    }],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];

        assert!(state.apply_block(&block).is_err());
    }

    #[test]
    fn swap_lock_and_settlement_move_ht_via_locked_balance() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury.clone(),
            requester.address(),
        );
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let quote = signed_sell_quote(
            &validator_a,
            requester.address(),
            2 * HEALTH_CHECK_BASE_COST,
            Utc::now() + chrono::Duration::seconds(30),
        );

        let lock_tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::SwapLock {
                        quote: quote.clone(),
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let lock_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![lock_tx],
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
        let mut lock_block = lock_block;
        lock_block.approvals = vec![
            approval_for(&validator_a, &lock_block),
            approval_for(&validator_b, &lock_block),
        ];
        state.apply_block(&lock_block).unwrap();

        assert_eq!(
            state.account(&requester.address()).balance,
            HEALTH_CHECK_BASE_COST * 4
        );
        assert_eq!(
            state.account(&requester.address()).locked_balance,
            2 * HEALTH_CHECK_BASE_COST
        );
        assert_eq!(
            state.spendable_balance(&requester.address()),
            2 * HEALTH_CHECK_BASE_COST
        );

        let settle_tx = validator_a
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::SwapSettle {
                        quote_id: quote.quote.quote_id.clone(),
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let settle_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: lock_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![settle_tx],
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
        let mut settle_block = settle_block;
        settle_block.approvals = vec![
            approval_for(&validator_a, &settle_block),
            approval_for(&validator_b, &settle_block),
        ];
        state.apply_block(&settle_block).unwrap();

        assert_eq!(
            state.account(&requester.address()).balance,
            2 * HEALTH_CHECK_BASE_COST
        );
        assert_eq!(state.account(&requester.address()).locked_balance, 0);
        assert_eq!(state.account(&treasury).balance, 2 * HEALTH_CHECK_BASE_COST);
        assert!(!state.pending_swap_locks.contains_key(&quote.quote.quote_id));
    }

    #[test]
    fn swap_lock_can_be_cancelled_after_expiry() {
        let requester = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();

        let genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            requester.address(),
        );
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let quote = signed_sell_quote(
            &validator_a,
            requester.address(),
            HEALTH_CHECK_BASE_COST,
            Utc::now() + chrono::Duration::seconds(1),
        );

        let lock_tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::SwapLock {
                        quote: quote.clone(),
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let lock_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: Utc::now(),
                    transactions: vec![lock_tx],
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
        let mut lock_block = lock_block;
        lock_block.approvals = vec![
            approval_for(&validator_a, &lock_block),
            approval_for(&validator_b, &lock_block),
        ];
        state.apply_block(&lock_block).unwrap();

        let cancel_tx = requester
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 2,
                    created_at: Utc::now(),
                    kind: TransactionKind::SwapCancel {
                        quote_id: quote.quote.quote_id.clone(),
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let cancel_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: lock_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at: quote.quote.expires_at + chrono::Duration::seconds(1),
                    transactions: vec![cancel_tx],
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
        let mut cancel_block = cancel_block;
        cancel_block.approvals = vec![
            approval_for(&validator_a, &cancel_block),
            approval_for(&validator_b, &cancel_block),
        ];
        state.apply_block(&cancel_block).unwrap();

        assert_eq!(
            state.account(&requester.address()).balance,
            HEALTH_CHECK_BASE_COST * 4
        );
        assert_eq!(state.account(&requester.address()).locked_balance, 0);
        assert!(!state.pending_swap_locks.contains_key(&quote.quote.quote_id));
    }

    #[test]
    fn storage_proof_pays_host_one_token_per_64mib_second() {
        let owner = Wallet::generate();
        let host = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();
        let mut genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            owner.address(),
        );
        genesis
            .storage_airdrops
            .insert(owner.address(), MICRO_ST * 2);
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let created_at = Utc::now();
        let chunk_hash = "11".repeat(32);
        let spec = StorageContractSpec {
            contract_id: "storage-1".into(),
            host: host.address(),
            mode: StorageMode::Encrypted,
            size_bytes: STORAGE_BILLING_QUANTUM_BYTES,
            chunk_size_bytes: STORAGE_BILLING_QUANTUM_BYTES,
            merkle_root: chunk_hash.clone(),
            duration_secs: 10,
            proof_interval_secs: 10,
            proof_sample_count: 1,
            reward_rate_per_64mib_second: MICRO_ST,
        };
        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::StorageCreate {
                        spec: spec.clone(),
                        prepaid_balance: MICRO_ST * 2,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![
            approval_for(&validator_a, &create_block),
            approval_for(&validator_b, &create_block),
        ];
        state.apply_block(&create_block).unwrap();

        let proof_at = created_at + chrono::Duration::seconds(1);
        let challenge_seed = storage_challenge_seed(
            "testnet",
            &spec.contract_id,
            &create_block.hash,
            created_at,
            proof_at,
            &spec.merkle_root,
        )
        .unwrap();
        let challenge_indices =
            storage_challenge_indices(&challenge_seed, storage_chunk_count(&spec), 1).unwrap();
        let proof_receipt = |validator: &Wallet| {
            validator
                .sign_storage_proof_receipt(SignedStorageProofReceipt {
                    id: String::new(),
                    body: StorageProofReceiptBody {
                        chain_id: "testnet".into(),
                        contract_id: spec.contract_id.clone(),
                        host: host.address(),
                        validator: String::new(),
                        window_start: created_at,
                        window_end: proof_at,
                        observed_at: proof_at,
                        bytes_stored: spec.size_bytes,
                        merkle_root: spec.merkle_root.clone(),
                        challenge_seed: challenge_seed.clone(),
                        samples: vec![StorageProofSample {
                            chunk_index: challenge_indices[0],
                            chunk_hash: chunk_hash.clone(),
                            proof: Vec::new(),
                        }],
                        success: true,
                        error: None,
                    },
                    signature: String::new(),
                })
                .unwrap()
        };

        let proof_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at: proof_at,
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: Vec::new(),
                    confirmation_batches: Vec::new(),
                    storage_proof_batches: vec![StorageProofBatch {
                        contract_id: spec.contract_id.clone(),
                        receipts: vec![proof_receipt(&validator_a), proof_receipt(&validator_b)],
                    }],
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut proof_block = proof_block;
        proof_block.approvals = vec![
            approval_for(&validator_a, &proof_block),
            approval_for(&validator_b, &proof_block),
        ];
        state.apply_block(&proof_block).unwrap();

        assert_eq!(state.account(&host.address()).storage_balance, MICRO_ST);
        let contract = state.storage_contracts.get(&spec.contract_id).unwrap();
        assert_eq!(contract.prepaid_balance, MICRO_ST);
        assert_eq!(contract.total_paid, MICRO_ST);
        assert_eq!(contract.proof_count, 1);
    }

    #[test]
    fn domain_lease_costs_one_dns_per_subdomain_second() {
        let owner = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();
        let mut genesis = test_genesis(
            &[validator_a.address(), validator_b.address()],
            treasury,
            owner.address(),
        );
        genesis
            .storage_airdrops
            .insert(owner.address(), MICRO_ST * 2);
        genesis.dns_airdrops.insert(owner.address(), MICRO_DNS * 2);
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let storage_spec = StorageContractSpec {
            contract_id: "site-contract".to_string(),
            host: validator_b.address(),
            mode: StorageMode::PublicRaw { manifest: None },
            size_bytes: 1024,
            chunk_size_bytes: 1024,
            merkle_root: "00".repeat(32),
            duration_secs: 60,
            proof_interval_secs: 10,
            proof_sample_count: 1,
            reward_rate_per_64mib_second: MICRO_ST,
        };
        let offering_tx = validator_a
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::DomainOfferingCreate {
                        offering_id: "example-pages".to_string(),
                        suffix: "pages.example.com".to_string(),
                        gateway_url: "https://gateway.example.com".to_string(),
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let storage_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at: Utc::now(),
                    kind: TransactionKind::StorageCreate {
                        spec: storage_spec,
                        prepaid_balance: MICRO_ST,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let lease_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 2,
                    created_at: Utc::now(),
                    kind: TransactionKind::DomainLeaseCreate {
                        offering_id: "example-pages".to_string(),
                        label: "alice".to_string(),
                        target_contract_id: "site-contract".to_string(),
                        duration_secs: 1,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let start = Utc::now();
        let block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: start,
                    transactions: vec![offering_tx, storage_tx, lease_tx],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];
        state.apply_block(&block).unwrap();

        let lease = state.domain_leases.values().next().unwrap().clone();
        assert_eq!(lease.fqdn, "alice.pages.example.com");
        assert_eq!(lease.prepaid_balance, MICRO_DNS);
        assert_eq!(state.account(&owner.address()).dns_balance, MICRO_DNS);

        let tick_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 3,
                    created_at: Utc::now(),
                    kind: TransactionKind::DnsTransfer {
                        to: owner.address(),
                        amount: MICRO_DNS,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: state.last_block_hash.clone(),
                    proposer: String::new(),
                    proposed_at: start + chrono::Duration::seconds(1),
                    transactions: vec![tick_tx],
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
        let mut block = block;
        block.approvals = vec![
            approval_for(&validator_a, &block),
            approval_for(&validator_b, &block),
        ];
        state.apply_block(&block).unwrap();

        let lease = state.domain_leases.values().next().unwrap();
        assert!(matches!(lease.status, DomainLeaseStatus::Expired));
        assert_eq!(lease.prepaid_balance, 0);
        assert_eq!(state.account(&validator_a.address()).dns_balance, MICRO_DNS);
    }

    #[test]
    fn monitor_success_observation_marks_slot_ok() {
        let owner = Wallet::generate();
        let validator = Wallet::generate();
        let treasury = validator.address();
        let created_at = Utc::now();
        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: treasury.clone(),
            validators: vec![validator.address()],
            chain_started_at: created_at,
            block_time_secs: 3,
            min_health_receipts: 1,
            airdrops: BTreeMap::from([(owner.address(), HEALTH_CHECK_BASE_COST * 4)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let spec = sample_monitor_spec("backup-nightly", created_at);

        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::MonitorCreate {
                        spec: spec.clone(),
                        initial_budget: HEALTH_CHECK_BASE_COST,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![approval_for(&validator, &create_block)];
        state.apply_block(&create_block).unwrap();

        let observed_at = created_at + chrono::Duration::seconds(65);
        let observation = validator
            .sign_heartbeat_observation(SignedHeartbeatObservation {
                id: String::new(),
                body: HeartbeatObservationBody {
                    chain_id: "testnet".into(),
                    monitor_id: spec.monitor_id.clone(),
                    slot_key: schedule_current_slot_start(&spec.schedule, observed_at)
                        .unwrap()
                        .to_rfc3339(),
                    signal: HeartbeatSignal::Success,
                    observed_at,
                    observed_by: String::new(),
                    body_sha256: None,
                    body_sample: None,
                    auth_mode: HeartbeatAuthMode::SecretUrl,
                    client_signature: None,
                    client_key_id: None,
                    client_timestamp: None,
                    client_nonce: None,
                },
                signature: String::new(),
            })
            .unwrap();

        let heartbeat_block = validator
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at: observed_at,
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: vec![observation],
                    monitor_evaluations: vec![MonitorEvaluation {
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: schedule_current_slot_start(&spec.schedule, observed_at)
                            .unwrap()
                            .to_rfc3339(),
                        kind: MonitorEvaluationKind::SlotSatisfied,
                        observed_at,
                    }],
                    confirmation_batches: Vec::new(),
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut heartbeat_block = heartbeat_block;
        heartbeat_block.approvals = vec![approval_for(&validator, &heartbeat_block)];
        state.apply_block(&heartbeat_block).unwrap();

        let slot_key = schedule_current_slot_start(&spec.schedule, observed_at)
            .unwrap()
            .to_rfc3339();
        let slot = state
            .monitor_slot_history
            .get(&spec.monitor_id)
            .and_then(|slots| slots.get(&slot_key))
            .cloned()
            .unwrap();
        assert_eq!(slot.status, MonitorSlotStatus::Ok);
        assert_eq!(
            state.monitors.get(&spec.monitor_id).unwrap().status,
            MonitorStatus::Up
        );
    }

    #[test]
    fn monitor_missed_slot_creates_alert_fact() {
        let owner = Wallet::generate();
        let validator = Wallet::generate();
        let treasury = validator.address();
        let created_at = Utc::now();
        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: treasury.clone(),
            validators: vec![validator.address()],
            chain_started_at: created_at,
            block_time_secs: 3,
            min_health_receipts: 1,
            airdrops: BTreeMap::from([(owner.address(), HEALTH_CHECK_BASE_COST * 4)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let spec = sample_monitor_spec("billing-hourly", created_at);

        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::MonitorCreate {
                        spec: spec.clone(),
                        initial_budget: HEALTH_CHECK_BASE_COST * 2,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![approval_for(&validator, &create_block)];
        state.apply_block(&create_block).unwrap();

        let slot_start = created_at + chrono::Duration::seconds(60);
        let proposed_at = slot_start + chrono::Duration::seconds(20);
        let missed_block = validator
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at,
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: vec![MonitorEvaluation {
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: slot_start.to_rfc3339(),
                        kind: MonitorEvaluationKind::SlotMissed,
                        observed_at: proposed_at,
                    }],
                    confirmation_batches: Vec::new(),
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut missed_block = missed_block;
        missed_block.approvals = vec![approval_for(&validator, &missed_block)];
        state.apply_block(&missed_block).unwrap();

        let slot = state
            .monitor_slot_history
            .get(&spec.monitor_id)
            .and_then(|slots| slots.get(&slot_start.to_rfc3339()))
            .cloned()
            .unwrap();
        assert_eq!(slot.status, MonitorSlotStatus::MissedUnconfirmed);
        assert_eq!(
            state.monitors.get(&spec.monitor_id).unwrap().status,
            MonitorStatus::Late
        );
        assert!(
            state
                .alert_facts
                .values()
                .any(|fact| fact.monitor_id == spec.monitor_id
                    && fact.slot_key == slot_start.to_rfc3339())
        );
    }

    #[test]
    fn delegated_confirmation_batch_marks_monitor_down() {
        let owner = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let agent_a = Wallet::generate();
        let agent_b = Wallet::generate();
        let treasury = validator_a.address();
        let created_at = Utc::now();
        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: treasury.clone(),
            validators: vec![validator_a.address(), validator_b.address()],
            chain_started_at: created_at,
            block_time_secs: 3,
            min_health_receipts: 2,
            airdrops: BTreeMap::from([(owner.address(), HEALTH_CHECK_BASE_COST * 8)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let mut spec = sample_monitor_spec("payments-delegated", created_at);
        if let MonitorPathway::Heartbeat { miss_policy, .. } = &mut spec.pathway {
            *miss_policy = MissPolicy::ConfirmWithDelegatedAgents {
                fanout: ProbeFanoutPolicy::OnePerValidator,
                require_region_diversity: 2,
            };
        }

        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::MonitorCreate {
                        spec: spec.clone(),
                        initial_budget: HEALTH_CHECK_BASE_COST * 4,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![
            approval_for(&validator_a, &create_block),
            approval_for(&validator_b, &create_block),
        ];
        state.apply_block(&create_block).unwrap();

        let slot_start = created_at + chrono::Duration::seconds(60);
        let slot_key = slot_start.to_rfc3339();
        let proposed_at = slot_start + chrono::Duration::seconds(20);
        let request_id = monitor_confirmation_request_id(&spec.monitor_id, &slot_key);
        let tx_hash = monitor_confirmation_tx_hash(&spec.monitor_id, &slot_key).unwrap();

        let validator_receipt = |wallet: &Wallet| {
            wallet
                .sign_receipt(SignedHealthReceipt {
                    id: String::new(),
                    body: crate::protocol::HealthReceiptBody {
                        chain_id: "testnet".into(),
                        tx_hash: tx_hash.clone(),
                        request_id: request_id.clone(),
                        executor: String::new(),
                        observed_at: proposed_at,
                        response_status: Some(503),
                        latency_ms: 25,
                        success: false,
                        assertion_results: Vec::new(),
                        response_headers: BTreeMap::new(),
                        response_body_sample: None,
                        error: Some("connection refused".into()),
                    },
                    signature: String::new(),
                })
                .unwrap()
        };
        let delegated_receipt =
            |agent: &Wallet, parent_validator: &Wallet, lease_id: &str, region: &str| {
                agent
                    .sign_delegated_probe_receipt(SignedDelegatedProbeReceipt {
                        id: String::new(),
                        body: crate::protocol::DelegatedProbeReceiptBody {
                            chain_id: "testnet".into(),
                            monitor_id: spec.monitor_id.clone(),
                            slot_key: slot_key.clone(),
                            agent_public_key: String::new(),
                            parent_validator: parent_validator.address(),
                            lease_id: Some(lease_id.into()),
                            request_id: Some(request_id.clone()),
                            region: Some(region.into()),
                            network: Some("public".into()),
                            observed_at: proposed_at,
                            response_status: Some(503),
                            latency_ms: 25,
                            success: false,
                            assertion_results: Vec::new(),
                            response_headers: BTreeMap::new(),
                            response_body_sample: None,
                            error: Some("connection refused".into()),
                        },
                        signature: String::new(),
                    })
                    .unwrap()
            };

        let batch = MonitorConfirmationBatch {
            monitor_id: spec.monitor_id.clone(),
            slot_key: slot_key.clone(),
            validator_receipts: vec![
                validator_receipt(&validator_a),
                validator_receipt(&validator_b),
            ],
            delegated_receipts: vec![
                delegated_receipt(&agent_a, &validator_a, "lease-a", "us-west"),
                delegated_receipt(&agent_b, &validator_b, "lease-b", "eu-central"),
            ],
        };

        let missed_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at,
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: vec![MonitorEvaluation {
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: slot_key.clone(),
                        kind: MonitorEvaluationKind::SlotMissed,
                        observed_at: proposed_at,
                    }],
                    confirmation_batches: vec![batch],
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut missed_block = missed_block;
        missed_block.approvals = vec![
            approval_for(&validator_a, &missed_block),
            approval_for(&validator_b, &missed_block),
        ];
        state.apply_block(&missed_block).unwrap();

        let slot = state
            .monitor_slot_history
            .get(&spec.monitor_id)
            .and_then(|slots| slots.get(&slot_key))
            .cloned()
            .unwrap();
        assert_eq!(slot.status, MonitorSlotStatus::DownConfirmed);
        assert_eq!(
            state.monitors.get(&spec.monitor_id).unwrap().status,
            MonitorStatus::Down
        );
    }

    #[test]
    fn delegated_confirmation_batch_rejects_insufficient_region_diversity() {
        let owner = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let agent_a = Wallet::generate();
        let agent_b = Wallet::generate();
        let treasury = validator_a.address();
        let created_at = Utc::now();
        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: treasury.clone(),
            validators: vec![validator_a.address(), validator_b.address()],
            chain_started_at: created_at,
            block_time_secs: 3,
            min_health_receipts: 2,
            airdrops: BTreeMap::from([(owner.address(), HEALTH_CHECK_BASE_COST * 8)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let mut spec = sample_monitor_spec("payments-regions", created_at);
        if let MonitorPathway::Heartbeat { miss_policy, .. } = &mut spec.pathway {
            *miss_policy = MissPolicy::ConfirmWithDelegatedAgents {
                fanout: ProbeFanoutPolicy::OnePerValidator,
                require_region_diversity: 2,
            };
        }

        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::MonitorCreate {
                        spec: spec.clone(),
                        initial_budget: HEALTH_CHECK_BASE_COST * 4,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![
            approval_for(&validator_a, &create_block),
            approval_for(&validator_b, &create_block),
        ];
        state.apply_block(&create_block).unwrap();

        let slot_start = created_at + chrono::Duration::seconds(60);
        let slot_key = slot_start.to_rfc3339();
        let proposed_at = slot_start + chrono::Duration::seconds(20);
        let request_id = monitor_confirmation_request_id(&spec.monitor_id, &slot_key);
        let tx_hash = monitor_confirmation_tx_hash(&spec.monitor_id, &slot_key).unwrap();

        let validator_receipt = |wallet: &Wallet| {
            wallet
                .sign_receipt(SignedHealthReceipt {
                    id: String::new(),
                    body: crate::protocol::HealthReceiptBody {
                        chain_id: "testnet".into(),
                        tx_hash: tx_hash.clone(),
                        request_id: request_id.clone(),
                        executor: String::new(),
                        observed_at: proposed_at,
                        response_status: Some(503),
                        latency_ms: 25,
                        success: false,
                        assertion_results: Vec::new(),
                        response_headers: BTreeMap::new(),
                        response_body_sample: None,
                        error: Some("connection refused".into()),
                    },
                    signature: String::new(),
                })
                .unwrap()
        };
        let delegated_receipt = |agent: &Wallet, parent_validator: &Wallet, lease_id: &str| {
            agent
                .sign_delegated_probe_receipt(SignedDelegatedProbeReceipt {
                    id: String::new(),
                    body: crate::protocol::DelegatedProbeReceiptBody {
                        chain_id: "testnet".into(),
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: slot_key.clone(),
                        agent_public_key: String::new(),
                        parent_validator: parent_validator.address(),
                        lease_id: Some(lease_id.into()),
                        request_id: Some(request_id.clone()),
                        region: Some("us-west".into()),
                        network: Some("public".into()),
                        observed_at: proposed_at,
                        response_status: Some(503),
                        latency_ms: 25,
                        success: false,
                        assertion_results: Vec::new(),
                        response_headers: BTreeMap::new(),
                        response_body_sample: None,
                        error: Some("connection refused".into()),
                    },
                    signature: String::new(),
                })
                .unwrap()
        };

        let batch = MonitorConfirmationBatch {
            monitor_id: spec.monitor_id.clone(),
            slot_key: slot_key.clone(),
            validator_receipts: vec![
                validator_receipt(&validator_a),
                validator_receipt(&validator_b),
            ],
            delegated_receipts: vec![
                delegated_receipt(&agent_a, &validator_a, "lease-a"),
                delegated_receipt(&agent_b, &validator_b, "lease-b"),
            ],
        };

        let missed_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at,
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: Vec::new(),
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: vec![MonitorEvaluation {
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: slot_key.clone(),
                        kind: MonitorEvaluationKind::SlotMissed,
                        observed_at: proposed_at,
                    }],
                    confirmation_batches: vec![batch],
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut missed_block = missed_block;
        missed_block.approvals = vec![
            approval_for(&validator_a, &missed_block),
            approval_for(&validator_b, &missed_block),
        ];
        let error = state.apply_block(&missed_block).unwrap_err();
        assert!(error.to_string().contains("delegated regions"));
    }

    #[test]
    fn scheduled_browser_monitor_slot_charges_budget_and_marks_slot_ok() {
        let owner = Wallet::generate();
        let validator_a = Wallet::generate();
        let validator_b = Wallet::generate();
        let treasury = validator_a.address();
        let created_at = Utc::now();
        let genesis = GenesisConfig {
            chain_id: "testnet".into(),
            treasury: treasury.clone(),
            validators: vec![validator_a.address(), validator_b.address()],
            chain_started_at: created_at,
            block_time_secs: 3,
            min_health_receipts: 2,
            airdrops: BTreeMap::from([(owner.address(), HEALTH_CHECK_BASE_COST * 12)]),
            storage_airdrops: BTreeMap::new(),
            compute_airdrops: BTreeMap::new(),
            dns_airdrops: BTreeMap::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let spec = sample_browser_monitor_spec(
            "browser-hourly",
            created_at,
            &owner.address(),
            &validator_a.address(),
        );
        let package = spec.browser_package().unwrap().clone();
        let slot_cost = crate::protocol::monitor_browser_slot_cost(&package).unwrap();

        let create_tx = owner
            .sign_transaction(SignedTransaction {
                hash: String::new(),
                signer: String::new(),
                body: TransactionBody {
                    chain_id: "testnet".into(),
                    nonce: 1,
                    created_at,
                    kind: TransactionKind::MonitorCreate {
                        spec: spec.clone(),
                        initial_budget: slot_cost * 2,
                    },
                },
                signature: String::new(),
            })
            .unwrap();
        let create_block = validator_a
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 1,
                    view: 0,
                    previous_hash: "genesis".into(),
                    proposer: String::new(),
                    proposed_at: created_at,
                    transactions: vec![create_tx],
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
        let mut create_block = create_block;
        create_block.approvals = vec![
            approval_for(&validator_a, &create_block),
            approval_for(&validator_b, &create_block),
        ];
        state.apply_block(&create_block).unwrap();

        let slot_key = created_at.to_rfc3339();
        let tx_hash = monitor_browser_tx_hash(&spec.monitor_id, &slot_key).unwrap();
        let request_id = monitor_browser_request_id(&spec.monitor_id, &slot_key);
        let package_hash = crate::browser::browser_package_hash(&package).unwrap();
        let runtime_hash = crate::browser::browser_runtime_hash(&package.runtime).unwrap();
        let observed_at = created_at + chrono::Duration::seconds(61);
        let sign_receipt = |validator: &Wallet| {
            validator
                .sign_browser_receipt(SignedBrowserReceipt {
                    id: String::new(),
                    body: BrowserReceiptBody {
                        chain_id: "testnet".into(),
                        tx_hash: tx_hash.clone(),
                        request_id: request_id.clone(),
                        monitor_id: Some(spec.monitor_id.clone()),
                        slot_key: Some(slot_key.clone()),
                        executor: String::new(),
                        observed_at,
                        package_hash: package_hash.clone(),
                        runtime_hash: runtime_hash.clone(),
                        latency_ms: 1_250,
                        success: true,
                        failed_step_index: None,
                        final_url: Some("https://example.com/dashboard".into()),
                        outcome_class: BrowserOutcomeClass::Success,
                        console_error_count: 0,
                        network_error_count: 0,
                        screenshot_artifact: None,
                        trace_artifact: None,
                        video_artifact: None,
                        error: None,
                    },
                    signature: String::new(),
                })
                .unwrap()
        };

        let browser_block = validator_b
            .sign_block(SignedBlock {
                hash: String::new(),
                body: BlockBody {
                    chain_id: "testnet".into(),
                    height: 2,
                    view: 0,
                    previous_hash: create_block.hash.clone(),
                    proposer: String::new(),
                    proposed_at: created_at + chrono::Duration::seconds(65),
                    transactions: Vec::new(),
                    health_batches: Vec::new(),
                    browser_batches: Vec::new(),
                    compute_batches: Vec::new(),
                    monitor_browser_batches: vec![MonitorBrowserBatch {
                        monitor_id: spec.monitor_id.clone(),
                        slot_key: slot_key.clone(),
                        receipts: vec![sign_receipt(&validator_a), sign_receipt(&validator_b)],
                    }],
                    heartbeat_observations: Vec::new(),
                    monitor_evaluations: Vec::new(),
                    confirmation_batches: Vec::new(),
                    storage_proof_batches: Vec::new(),
                },
                signature: String::new(),
                approvals: Vec::new(),
            })
            .unwrap();
        let mut browser_block = browser_block;
        browser_block.approvals = vec![
            approval_for(&validator_a, &browser_block),
            approval_for(&validator_b, &browser_block),
        ];
        state.apply_block(&browser_block).unwrap();

        let slot = state
            .monitor_slot_history
            .get(&spec.monitor_id)
            .unwrap()
            .get(&slot_key)
            .unwrap();
        assert_eq!(slot.status, MonitorSlotStatus::Ok);
        assert_eq!(slot.confirmation_success, Some(true));
        let monitor = state.monitors.get(&spec.monitor_id).unwrap();
        assert_eq!(monitor.status, MonitorStatus::Up);
        assert_eq!(monitor.budget_balance, slot_cost);
    }
}
