use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use bs58::{decode as b58decode, encode as b58encode};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};

use crate::browser::{
    SignedBrowserAgentLease, SignedBrowserReceipt, SignedDelegatedBrowserReceipt,
};
use crate::compute::{
    SignedComputeReceipt, SignedComputeShardLease, SignedDelegatedComputeShardReceipt,
};
use crate::protocol::{
    Address, SignedBlock, SignedBlockApproval, SignedDelegatedProbeReceipt, SignedHealthReceipt,
    SignedHeartbeatObservation, SignedProbeAgentLease, SignedStorageProofReceipt, SignedSwapQuote,
    SignedTransaction, canonical_bytes, compute_hash,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    pub created_at: DateTime<Utc>,
    pub address: Address,
    pub public_key_base58: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypair_base58: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_keypair: Option<EncryptedKeypair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeypair {
    pub kdf: String,
    pub cipher: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Clone)]
pub struct Wallet {
    signing_key: SigningKey,
}

impl Wallet {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_file(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let data = fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read wallet {}", path.as_ref().display()))?;
        let file: WalletFile = serde_json::from_str(&data)?;
        Self::from_wallet_file(&file, passphrase)
    }

    pub fn to_file_insecure_plaintext(&self) -> WalletFile {
        WalletFile {
            created_at: Utc::now(),
            address: self.address(),
            public_key_base58: self.public_key_base58(),
            keypair_base58: Some(self.keypair_base58()),
            encrypted_keypair: None,
        }
    }

    pub fn to_file_encrypted(&self, passphrase: &str) -> Result<WalletFile> {
        let raw_keypair = self.raw_keypair_bytes();
        let encrypted_keypair = encrypt_keypair(&raw_keypair, passphrase)?;
        Ok(WalletFile {
            created_at: Utc::now(),
            address: self.address(),
            public_key_base58: self.public_key_base58(),
            keypair_base58: None,
            encrypted_keypair: Some(encrypted_keypair),
        })
    }

    pub fn save_insecure_plaintext(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = self.to_file_insecure_plaintext();
        let json = serde_json::to_string_pretty(&file)?;
        fs::write(path.as_ref(), json)
            .with_context(|| format!("failed to write wallet {}", path.as_ref().display()))?;
        Ok(())
    }

    pub fn save_encrypted(&self, path: impl AsRef<Path>, passphrase: &str) -> Result<()> {
        let file = self.to_file_encrypted(passphrase)?;
        let json = serde_json::to_string_pretty(&file)?;
        fs::write(path.as_ref(), json)
            .with_context(|| format!("failed to write wallet {}", path.as_ref().display()))?;
        Ok(())
    }

    pub fn address(&self) -> Address {
        b58encode(self.signing_key.verifying_key().to_bytes()).into_string()
    }

    pub fn public_key_base58(&self) -> String {
        self.address()
    }

    pub fn keypair_base58(&self) -> String {
        b58encode(self.raw_keypair_bytes()).into_string()
    }

    pub fn sign_bytes(&self, payload: &[u8]) -> String {
        let signature = self.signing_key.sign(payload);
        b58encode(signature.to_bytes()).into_string()
    }

    pub fn sign_transaction(&self, mut tx: SignedTransaction) -> Result<SignedTransaction> {
        tx.signer = self.address();
        tx.hash = compute_hash(&(tx.signer.clone(), &tx.body))?;
        tx.signature = self.sign_bytes(&canonical_bytes(&(
            tx.signer.clone(),
            &tx.body,
            tx.hash.clone(),
        ))?);
        Ok(tx)
    }

    pub fn sign_receipt(&self, mut receipt: SignedHealthReceipt) -> Result<SignedHealthReceipt> {
        receipt.body.executor = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_browser_receipt(
        &self,
        mut receipt: SignedBrowserReceipt,
    ) -> Result<SignedBrowserReceipt> {
        receipt.body.executor = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_delegated_browser_receipt(
        &self,
        mut receipt: SignedDelegatedBrowserReceipt,
    ) -> Result<SignedDelegatedBrowserReceipt> {
        receipt.body.agent_public_key = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_browser_agent_lease(
        &self,
        mut lease: SignedBrowserAgentLease,
    ) -> Result<SignedBrowserAgentLease> {
        lease.body.parent_validator = self.address();
        lease.id = compute_hash(&lease.body)?;
        lease.signature = self.sign_bytes(&canonical_bytes(&(lease.id.clone(), &lease.body))?);
        Ok(lease)
    }

    pub fn sign_compute_receipt(
        &self,
        mut receipt: SignedComputeReceipt,
    ) -> Result<SignedComputeReceipt> {
        receipt.body.executor = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_compute_shard_lease(
        &self,
        mut lease: SignedComputeShardLease,
    ) -> Result<SignedComputeShardLease> {
        lease.body.parent_validator = self.address();
        lease.id = compute_hash(&lease.body)?;
        lease.signature = self.sign_bytes(&canonical_bytes(&(lease.id.clone(), &lease.body))?);
        Ok(lease)
    }

    pub fn sign_delegated_compute_shard_receipt(
        &self,
        mut receipt: SignedDelegatedComputeShardReceipt,
    ) -> Result<SignedDelegatedComputeShardReceipt> {
        receipt.body.agent_public_key = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_heartbeat_observation(
        &self,
        mut observation: SignedHeartbeatObservation,
    ) -> Result<SignedHeartbeatObservation> {
        observation.body.observed_by = self.address();
        observation.id = compute_hash(&observation.body)?;
        observation.signature = self.sign_bytes(&canonical_bytes(&(
            observation.id.clone(),
            &observation.body,
        ))?);
        Ok(observation)
    }

    pub fn sign_delegated_probe_receipt(
        &self,
        mut receipt: SignedDelegatedProbeReceipt,
    ) -> Result<SignedDelegatedProbeReceipt> {
        receipt.body.agent_public_key = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_storage_proof_receipt(
        &self,
        mut receipt: SignedStorageProofReceipt,
    ) -> Result<SignedStorageProofReceipt> {
        receipt.body.validator = self.address();
        receipt.id = compute_hash(&receipt.body)?;
        receipt.signature =
            self.sign_bytes(&canonical_bytes(&(receipt.id.clone(), &receipt.body))?);
        Ok(receipt)
    }

    pub fn sign_probe_agent_lease(
        &self,
        mut lease: SignedProbeAgentLease,
    ) -> Result<SignedProbeAgentLease> {
        lease.body.parent_validator = self.address();
        lease.id = compute_hash(&lease.body)?;
        lease.signature = self.sign_bytes(&canonical_bytes(&(lease.id.clone(), &lease.body))?);
        Ok(lease)
    }

    pub fn sign_block(&self, mut block: SignedBlock) -> Result<SignedBlock> {
        block.body.proposer = self.address();
        block.hash = compute_hash(&block.body)?;
        block.signature = self.sign_bytes(&canonical_bytes(&(block.hash.clone(), &block.body))?);
        Ok(block)
    }

    pub fn sign_block_approval(
        &self,
        mut approval: SignedBlockApproval,
    ) -> Result<SignedBlockApproval> {
        approval.body.approver = self.address();
        approval.id = compute_hash(&approval.body)?;
        approval.signature =
            self.sign_bytes(&canonical_bytes(&(approval.id.clone(), &approval.body))?);
        Ok(approval)
    }

    pub fn sign_swap_quote(&self, mut quote: SignedSwapQuote) -> Result<SignedSwapQuote> {
        quote.quoted_by = self.address();
        quote.signature = self.sign_bytes(&canonical_bytes(&(
            &quote.quote,
            quote.quoted_by.clone(),
            quote.quoted_at,
        ))?);
        Ok(quote)
    }

    fn from_wallet_file(file: &WalletFile, passphrase: Option<&str>) -> Result<Self> {
        let bytes = match (&file.keypair_base58, &file.encrypted_keypair) {
            (Some(keypair_base58), None) => b58decode(keypair_base58)
                .into_vec()
                .context("failed to decode wallet keypair")?,
            (None, Some(encrypted_keypair)) => {
                let passphrase =
                    passphrase.ok_or_else(|| anyhow::anyhow!("wallet passphrase is required"))?;
                decrypt_keypair(encrypted_keypair, passphrase)?
            }
            (Some(_), Some(_)) => {
                bail!("wallet file cannot contain both plaintext and encrypted keys")
            }
            (None, None) => bail!("wallet file is missing key material"),
        };
        if bytes.len() != 64 {
            bail!("wallet keypair must contain 64 bytes");
        }

        let secret: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid secret key length"))?;
        let public: [u8; 32] = bytes[32..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        if signing_key.verifying_key().to_bytes() != public {
            bail!("wallet public key does not match secret key");
        }

        let wallet = Self { signing_key };
        if wallet.address() != file.address {
            bail!("wallet address does not match encoded keypair");
        }
        Ok(wallet)
    }

    fn raw_keypair_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.signing_key.to_bytes());
        bytes[32..].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        bytes
    }
}

pub fn verify_address(address: &str) -> Result<VerifyingKey> {
    let bytes = b58decode(address)
        .into_vec()
        .context("failed to decode address")?;
    if bytes.len() != 32 {
        bail!("address must decode to 32 bytes");
    }
    let public: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid address bytes"))?;
    Ok(VerifyingKey::from_bytes(&public)?)
}

pub fn verify_transaction(tx: &SignedTransaction) -> Result<()> {
    let verifying_key = verify_address(&tx.signer)?;
    let signature = decode_signature(&tx.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(tx.signer.clone(), &tx.body, tx.hash.clone()))?,
        &signature,
    )?;

    let expected_hash = compute_hash(&(tx.signer.clone(), &tx.body))?;
    if expected_hash != tx.hash {
        bail!("transaction hash mismatch");
    }
    Ok(())
}

pub fn verify_receipt(receipt: &SignedHealthReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.executor)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("receipt id mismatch");
    }
    Ok(())
}

pub fn verify_browser_receipt(receipt: &SignedBrowserReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.executor)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("browser receipt id mismatch");
    }
    Ok(())
}

pub fn verify_delegated_browser_receipt(receipt: &SignedDelegatedBrowserReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.agent_public_key)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("delegated browser receipt id mismatch");
    }
    Ok(())
}

pub fn verify_browser_agent_lease(lease: &SignedBrowserAgentLease) -> Result<()> {
    let verifying_key = verify_address(&lease.body.parent_validator)?;
    let signature = decode_signature(&lease.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(lease.id.clone(), &lease.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&lease.body)?;
    if expected_id != lease.id {
        bail!("browser agent lease id mismatch");
    }
    Ok(())
}

pub fn verify_compute_receipt(receipt: &SignedComputeReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.executor)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("compute receipt id mismatch");
    }
    Ok(())
}

pub fn verify_compute_shard_lease(lease: &SignedComputeShardLease) -> Result<()> {
    let verifying_key = verify_address(&lease.body.parent_validator)?;
    let signature = decode_signature(&lease.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(lease.id.clone(), &lease.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&lease.body)?;
    if expected_id != lease.id {
        bail!("compute shard lease id mismatch");
    }
    Ok(())
}

pub fn verify_delegated_compute_shard_receipt(
    receipt: &SignedDelegatedComputeShardReceipt,
) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.agent_public_key)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("delegated compute shard receipt id mismatch");
    }
    Ok(())
}

pub fn verify_heartbeat_observation(observation: &SignedHeartbeatObservation) -> Result<()> {
    let verifying_key = verify_address(&observation.body.observed_by)?;
    let signature = decode_signature(&observation.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(observation.id.clone(), &observation.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&observation.body)?;
    if expected_id != observation.id {
        bail!("heartbeat observation id mismatch");
    }
    Ok(())
}

pub fn verify_delegated_probe_receipt(receipt: &SignedDelegatedProbeReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.agent_public_key)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("delegated probe receipt id mismatch");
    }
    Ok(())
}

pub fn verify_storage_proof_receipt(receipt: &SignedStorageProofReceipt) -> Result<()> {
    let verifying_key = verify_address(&receipt.body.validator)?;
    let signature = decode_signature(&receipt.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(receipt.id.clone(), &receipt.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&receipt.body)?;
    if expected_id != receipt.id {
        bail!("storage proof receipt id mismatch");
    }
    Ok(())
}

pub fn verify_probe_agent_lease(lease: &SignedProbeAgentLease) -> Result<()> {
    let verifying_key = verify_address(&lease.body.parent_validator)?;
    let signature = decode_signature(&lease.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(lease.id.clone(), &lease.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&lease.body)?;
    if expected_id != lease.id {
        bail!("probe agent lease id mismatch");
    }
    Ok(())
}

pub fn verify_block(block: &SignedBlock) -> Result<()> {
    let verifying_key = verify_address(&block.body.proposer)?;
    let signature = decode_signature(&block.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(block.hash.clone(), &block.body))?,
        &signature,
    )?;

    let expected_hash = compute_hash(&block.body)?;
    if expected_hash != block.hash {
        bail!("block hash mismatch");
    }
    Ok(())
}

pub fn verify_block_approval(approval: &SignedBlockApproval) -> Result<()> {
    let verifying_key = verify_address(&approval.body.approver)?;
    let signature = decode_signature(&approval.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(approval.id.clone(), &approval.body))?,
        &signature,
    )?;

    let expected_id = compute_hash(&approval.body)?;
    if expected_id != approval.id {
        bail!("block approval id mismatch");
    }
    Ok(())
}

pub fn verify_swap_quote(quote: &SignedSwapQuote) -> Result<()> {
    let verifying_key = verify_address(&quote.quoted_by)?;
    let signature = decode_signature(&quote.signature)?;
    verifying_key.verify(
        &canonical_bytes(&(&quote.quote, quote.quoted_by.clone(), quote.quoted_at))?,
        &signature,
    )?;
    Ok(())
}

pub fn verify_signed_message(
    public_key_base58: &str,
    payload: &[u8],
    signature_base58: &str,
) -> Result<()> {
    let bytes = b58decode(public_key_base58)
        .into_vec()
        .context("failed to decode public key")?;
    if bytes.len() != 32 {
        bail!("public key must decode to 32 bytes");
    }
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&array)?;
    let signature = decode_signature(signature_base58)?;
    verifying_key.verify(payload, &signature)?;
    Ok(())
}

fn encrypt_keypair(raw_keypair: &[u8], passphrase: &str) -> Result<EncryptedKeypair> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    thread_rng().fill_bytes(&mut salt);
    thread_rng().fill_bytes(&mut nonce);

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|error| anyhow::anyhow!("failed to derive wallet encryption key: {error}"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("failed to initialize wallet cipher"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), raw_keypair)
        .map_err(|_| anyhow::anyhow!("failed to encrypt wallet keypair"))?;

    Ok(EncryptedKeypair {
        kdf: "argon2id".into(),
        cipher: "xchacha20poly1305".into(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn decrypt_keypair(payload: &EncryptedKeypair, passphrase: &str) -> Result<Vec<u8>> {
    if payload.kdf != "argon2id" {
        bail!("unsupported wallet key derivation function");
    }
    if payload.cipher != "xchacha20poly1305" {
        bail!("unsupported wallet cipher");
    }
    let salt = hex::decode(&payload.salt_hex).context("failed to decode wallet salt")?;
    let nonce = hex::decode(&payload.nonce_hex).context("failed to decode wallet nonce")?;
    let ciphertext =
        hex::decode(&payload.ciphertext_hex).context("failed to decode wallet ciphertext")?;
    if nonce.len() != 24 {
        bail!("wallet nonce must contain 24 bytes");
    }

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|error| anyhow::anyhow!("failed to derive wallet encryption key: {error}"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("failed to initialize wallet cipher"))?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("failed to decrypt wallet keypair"))?;
    Ok(plaintext)
}

fn decode_signature(signature: &str) -> Result<Signature> {
    let bytes = b58decode(signature)
        .into_vec()
        .context("failed to decode signature")?;
    if bytes.len() != 64 {
        bail!("signature must contain 64 bytes");
    }
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
    Ok(Signature::from_bytes(&array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BlockApprovalBody, SwapQuote, TransactionBody, TransactionKind};

    #[test]
    fn wallet_round_trip_preserves_sol_style_lengths() {
        let wallet = Wallet::generate();
        let exported = wallet.to_file_insecure_plaintext();

        let decoded_keypair = b58decode(exported.keypair_base58.as_ref().unwrap())
            .into_vec()
            .unwrap();
        let decoded_address = b58decode(&exported.address).into_vec().unwrap();

        assert_eq!(decoded_keypair.len(), 64);
        assert_eq!(decoded_address.len(), 32);

        let restored = Wallet::from_wallet_file(&exported, None).unwrap();
        assert_eq!(wallet.address(), restored.address());
    }

    #[test]
    fn encrypted_wallet_round_trip_requires_passphrase() {
        let wallet = Wallet::generate();
        let exported = wallet.to_file_encrypted("test-passphrase").unwrap();
        assert!(exported.encrypted_keypair.is_some());
        assert!(exported.keypair_base58.is_none());

        assert!(Wallet::from_wallet_file(&exported, None).is_err());
        let restored = Wallet::from_wallet_file(&exported, Some("test-passphrase")).unwrap();
        assert_eq!(wallet.address(), restored.address());
    }

    #[test]
    fn signed_transaction_verifies() {
        let wallet = Wallet::generate();
        let tx = SignedTransaction {
            hash: String::new(),
            signer: String::new(),
            body: TransactionBody {
                chain_id: "test".into(),
                nonce: 1,
                created_at: Utc::now(),
                kind: TransactionKind::Transfer {
                    to: wallet.address(),
                    amount: 42,
                },
            },
            signature: String::new(),
        };

        let signed = wallet.sign_transaction(tx).unwrap();
        verify_transaction(&signed).unwrap();
    }

    #[test]
    fn signed_block_approval_verifies() {
        let wallet = Wallet::generate();
        let approval = SignedBlockApproval {
            id: String::new(),
            body: BlockApprovalBody {
                chain_id: "testnet".into(),
                height: 1,
                view: 0,
                previous_hash: "genesis".into(),
                block_hash: "abc123".into(),
                approver: String::new(),
                approved_at: Utc::now(),
            },
            signature: String::new(),
        };

        let signed = wallet.sign_block_approval(approval).unwrap();
        verify_block_approval(&signed).unwrap();
    }

    #[test]
    fn signed_swap_quote_verifies() {
        let wallet = Wallet::generate();
        let signed = wallet
            .sign_swap_quote(SignedSwapQuote {
                quote: SwapQuote {
                    chain_id: "testnet".into(),
                    quote_id: "quote-1".into(),
                    wallet: wallet.address(),
                    adapter: "fixed-usdc-demo".into(),
                    side: crate::protocol::SwapSide::Sell,
                    settlement_asset: crate::protocol::SettlementAsset::Usdc,
                    token_amount: 2_000_000,
                    settlement_amount: 2_000_000,
                    settlement_decimals: 6,
                    expires_at: Utc::now(),
                    notes: vec!["demo".into()],
                },
                quoted_by: String::new(),
                quoted_at: Utc::now(),
                signature: String::new(),
            })
            .unwrap();
        verify_swap_quote(&signed).unwrap();
    }
}
