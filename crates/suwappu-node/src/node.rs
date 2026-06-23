//! In-process Suwappu EVM state — the single authoritative mutable world-state.
//!
//! [`SuwappuNode`] owns:
//! - an [`InMemoryDB`] that persists across transactions (the "chain state"),
//! - a block counter,
//! - `txHash → receipt` and `txHash → tx` maps for RPC queries.
//!
//! All mutation goes through [`SuwappuNode::send_raw_transaction`] which
//! instant-mines (one tx = one block) via the suwappu EVM.

use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use revm::{
    context::result::{ExecutionResult, Output},
    context::TxEnv,
    context_interface::ContextTr,
    database::InMemoryDB,
    handler::EvmTr,
    primitives::{TxKind, U256 as RevmU256},
    state::AccountInfo,
    ExecuteCommitEvm,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use suwappu_revm::api::{builder::MonadBuilder, default_ctx::monad_context_with_db};

/// Gas limit used for a single block (1 billion — effectively unlimited for a
/// dev node; prevents block-gas-limit rejections while still allowing
/// `eth_estimateGas` to converge).
pub const BLOCK_GAS_LIMIT: u64 = 1_000_000_000;

/// Per-transaction gas limit cap for `eth_estimateGas` responses.
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Large balance (10_000 ETH in wei) pre-funded on standard dev accounts.
pub const PREFUND_WEI: u128 = 10_000 * 1_000_000_000_000_000_000u128;

/// The 10 well-known Anvil / Hardhat dev accounts derived from
/// `test test test test test test test test test test test junk` (m/44'/60'/0'/0/i).
pub const DEV_ACCOUNTS: [&str; 10] = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
    "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
    "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
];

// ─── Receipt ────────────────────────────────────────────────────────────────

/// Minimal transaction receipt stored in the node's receipt map.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// `0x1` success / `0x0` revert.
    pub status: String,
    /// Gas used by this transaction.
    pub gas_used: String,
    /// Contract address if this was a CREATE, otherwise `None`.
    pub contract_address: Option<String>,
    /// Block number this tx was mined in.
    pub block_number: String,
    /// Transaction hash.
    pub transaction_hash: String,
    /// Index within the block (always 0 for instant-mine).
    pub transaction_index: String,
    /// Block hash.
    pub block_hash: String,
    /// EVM logs (empty for now — sufficient for deploy + relayer).
    pub logs: Vec<serde_json::Value>,
    /// From address.
    pub from: String,
    /// To address (None for creates).
    pub to: Option<String>,
    /// Cumulative gas used (same as gas_used in instant-mine).
    pub cumulative_gas_used: String,
    /// Logs bloom (zeroed for dev node).
    pub logs_bloom: String,
    /// Transaction type (0x0 legacy, 0x2 EIP-1559).
    pub r#type: String,
    /// Effective gas price.
    pub effective_gas_price: String,
}

// ─── Stored Tx ──────────────────────────────────────────────────────────────

/// Minimal transaction stored for `eth_getTransactionByHash`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTx {
    /// Transaction hash.
    pub hash: String,
    /// Nonce.
    pub nonce: String,
    /// Block hash.
    pub block_hash: String,
    /// Block number.
    pub block_number: String,
    /// Index in block.
    pub transaction_index: String,
    /// From.
    pub from: String,
    /// To (None for creates).
    pub to: Option<String>,
    /// Value in wei.
    pub value: String,
    /// Gas limit.
    pub gas: String,
    /// Gas price.
    pub gas_price: String,
    /// Input data.
    pub input: String,
    /// Chain id.
    pub chain_id: Option<String>,
    /// Tx type.
    pub r#type: String,
}

// ─── NodeState (inner, behind Mutex) ────────────────────────────────────────

struct NodeState {
    db: InMemoryDB,
    block_number: u64,
    chain_id: u64,
    receipts: HashMap<B256, Receipt>,
    transactions: HashMap<B256, StoredTx>,
    /// Block hash by block number.
    block_hashes: HashMap<u64, B256>,
}

impl std::fmt::Debug for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeState")
            .field("block_number", &self.block_number)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl NodeState {
    fn new(chain_id: u64) -> Self {
        let mut db = InMemoryDB::default();

        // Pre-fund standard dev accounts.
        for addr_str in &DEV_ACCOUNTS {
            let addr: revm::primitives::Address =
                addr_str.parse().expect("valid dev account address");
            db.insert_account_info(
                addr,
                AccountInfo {
                    balance: RevmU256::from(PREFUND_WEI),
                    nonce: 0,
                    ..Default::default()
                },
            );
        }

        Self {
            db,
            block_number: 0,
            chain_id,
            receipts: HashMap::new(),
            transactions: HashMap::new(),
            block_hashes: HashMap::new(),
        }
    }
}

// ─── SuwappuNode (public, Arc-wrapped) ──────────────────────────────────────

/// The Suwappu dev-node.
///
/// Clone-cheap: wraps an `Arc<Mutex<NodeState>>`.
#[derive(Debug, Clone)]
pub struct SuwappuNode {
    state: Arc<Mutex<NodeState>>,
}

impl SuwappuNode {
    /// Construct a new dev node with the given chain ID.
    pub fn new(chain_id: u64) -> Self {
        Self { state: Arc::new(Mutex::new(NodeState::new(chain_id))) }
    }

    /// Return the configured chain ID.
    pub fn chain_id(&self) -> u64 {
        self.state.lock().unwrap().chain_id
    }

    /// Return the current block number.
    pub fn block_number(&self) -> u64 {
        self.state.lock().unwrap().block_number
    }

    /// Return account balance in wei as a `U256`.
    pub fn get_balance(&self, addr: Address) -> U256 {
        let state = self.state.lock().unwrap();
        let revm_addr = revm::primitives::Address::from(addr.into_array());
        state
            .db
            .cache
            .accounts
            .get(&revm_addr)
            .map(|a| {
                let bytes = a.info.balance.to_le_bytes::<32>();
                U256::from_le_slice(&bytes)
            })
            .unwrap_or(U256::ZERO)
    }

    /// Return account nonce.
    pub fn get_nonce(&self, addr: Address) -> u64 {
        let state = self.state.lock().unwrap();
        let revm_addr = revm::primitives::Address::from(addr.into_array());
        state.db.cache.accounts.get(&revm_addr).map(|a| a.info.nonce).unwrap_or(0)
    }

    /// Return deployed bytecode at address.
    pub fn get_code(&self, addr: Address) -> Bytes {
        let state = self.state.lock().unwrap();
        let revm_addr = revm::primitives::Address::from(addr.into_array());
        state
            .db
            .cache
            .accounts
            .get(&revm_addr)
            .and_then(|a| {
                if a.info.code_hash == revm::primitives::KECCAK_EMPTY {
                    None
                } else {
                    let code = state.db.cache.contracts.get(&a.info.code_hash)?;
                    Some(Bytes::copy_from_slice(code.bytes_slice()))
                }
            })
            .unwrap_or_default()
    }

    /// Execute a read-only call (no state mutation). Returns output bytes or an
    /// error string.
    pub fn eth_call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        data: Bytes,
        value: U256,
        gas_limit: Option<u64>,
    ) -> Result<Bytes, String> {
        let state = self.state.lock().unwrap();
        // Snapshot the DB by cloning it — we MUST NOT commit back.
        let db_snap = state.db.clone();
        let chain_id = state.chain_id;
        // Release lock before EVM execution (EVM takes time; snapshot is owned).
        drop(state);

        let from_revm = match from {
            Some(a) => revm::primitives::Address::from(a.into_array()),
            None => revm::primitives::Address::ZERO,
        };
        let value_revm = alloy_u256_to_revm(value);

        let kind = match to {
            Some(a) => TxKind::Call(revm::primitives::Address::from(a.into_array())),
            None => TxKind::Create,
        };

        let mut ctx = monad_context_with_db(db_snap);
        ctx.block.gas_limit = BLOCK_GAS_LIMIT;
        ctx.block.basefee = 0;
        // Disable checks for read-only calls: caller may be unfunded / wrong nonce.
        ctx.cfg.0.disable_balance_check = true;
        ctx.cfg.0.disable_block_gas_limit = true;
        ctx.cfg.0.disable_nonce_check = true;
        ctx.cfg.0.disable_base_fee = true;
        ctx.cfg.0.tx_chain_id_check = false;
        ctx.cfg.0.chain_id = chain_id;

        let mut evm = ctx.build_monad();

        let tx = TxEnv::builder()
            .caller(from_revm)
            .kind(kind)
            .nonce(0)
            .gas_limit(gas_limit.unwrap_or(DEFAULT_GAS_LIMIT))
            .gas_price(0)
            .value(value_revm)
            .data(revm::primitives::Bytes::copy_from_slice(&data))
            .build_fill();

        match evm.transact_commit(tx) {
            Ok(ExecutionResult::Success { output, .. }) => {
                let bytes = match output {
                    Output::Call(b) => b.to_vec(),
                    Output::Create(b, _) => b.to_vec(),
                };
                // Snapshot was consumed by EVM; original state.db was not touched.
                Ok(Bytes::from(bytes))
            }
            Ok(ExecutionResult::Revert { output, .. }) => {
                Err(format!("execution reverted: 0x{}", hex::encode(&output)))
            }
            Ok(ExecutionResult::Halt { reason, .. }) => {
                Err(format!("execution halted: {reason:?}"))
            }
            Err(e) => Err(format!("evm error: {e:?}")),
        }
    }

    /// Estimate gas for a call. Returns a conservative estimate.
    pub fn estimate_gas(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        data: Bytes,
        value: U256,
    ) -> Result<u64, String> {
        let state = self.state.lock().unwrap();
        let db_snap = state.db.clone();
        let chain_id = state.chain_id;
        drop(state);

        let from_revm = match from {
            Some(a) => revm::primitives::Address::from(a.into_array()),
            None => revm::primitives::Address::ZERO,
        };
        let value_revm = alloy_u256_to_revm(value);

        let kind = match to {
            Some(a) => TxKind::Call(revm::primitives::Address::from(a.into_array())),
            None => TxKind::Create,
        };

        let mut ctx = monad_context_with_db(db_snap);
        ctx.block.gas_limit = BLOCK_GAS_LIMIT;
        ctx.block.basefee = 0;
        ctx.cfg.0.disable_balance_check = true;
        ctx.cfg.0.disable_block_gas_limit = true;
        ctx.cfg.0.disable_nonce_check = true;
        ctx.cfg.0.disable_base_fee = true;
        ctx.cfg.0.tx_chain_id_check = false;
        ctx.cfg.0.chain_id = chain_id;

        let mut evm = ctx.build_monad();

        let tx = TxEnv::builder()
            .caller(from_revm)
            .kind(kind)
            .nonce(0)
            .gas_limit(DEFAULT_GAS_LIMIT)
            .gas_price(0)
            .value(value_revm)
            .data(revm::primitives::Bytes::copy_from_slice(&data))
            .build_fill();

        match evm.transact_commit(tx) {
            Ok(ExecutionResult::Success { gas_used, .. }) => {
                // gas used + 20% buffer, capped at DEFAULT_GAS_LIMIT.
                let estimate = (gas_used as u128 * 12 / 10) as u64;
                Ok(estimate.min(DEFAULT_GAS_LIMIT))
            }
            Ok(ExecutionResult::Revert { output, .. }) => {
                Err(format!("execution reverted: 0x{}", hex::encode(&output)))
            }
            Ok(ExecutionResult::Halt { reason, .. }) => {
                Err(format!("execution halted: {reason:?}"))
            }
            Err(e) => Err(format!("evm error: {e:?}")),
        }
    }

    /// Decode, validate, execute, and instant-mine a signed raw transaction.
    ///
    /// Returns the 32-byte transaction hash on success, or a JSON-RPC error
    /// string on failure. Execution failure (revert/halt) still returns a hash
    /// (with status 0); only decode/validation errors return `Err`.
    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<B256, String> {
        // ── Decode the RLP-encoded signed transaction ───────────────────────
        let envelope =
            TxEnvelope::decode(&mut &raw[..]).map_err(|e| format!("RLP decode error: {e}"))?;

        // Recover the sender (secp256k1 ecrecover).
        let sender_alloy =
            envelope.recover_signer().map_err(|e| format!("sender recovery failed: {e}"))?;

        // Map alloy Address → revm Address (same 20-byte layout).
        let sender = revm::primitives::Address::from(sender_alloy.into_array());

        // Compute the canonical tx hash (keccak256 of the full RLP).
        let tx_hash = keccak256(raw);

        // ── Extract the fields we need for TxEnv ────────────────────────────
        let TxFields {
            nonce,
            gas_limit,
            gas_price,
            to_alloy,
            value_alloy,
            input,
            tx_type,
            chain_id_opt,
        } = extract_tx_fields(&envelope)?;

        let kind = match to_alloy {
            Some(a) => TxKind::Call(revm::primitives::Address::from(a.into_array())),
            None => TxKind::Create,
        };

        let value_revm = alloy_u256_to_revm(value_alloy);
        let to_addr = to_alloy;

        // ── Lock state and run the EVM ───────────────────────────────────────
        let mut state = self.state.lock().unwrap();

        // Validate chain id (skip for legacy pre-EIP-155 txs where chain_id is None).
        if let Some(cid) = chain_id_opt {
            if cid != state.chain_id {
                return Err(format!("chain id mismatch: tx={cid} node={}", state.chain_id));
            }
        }

        let block_number = state.block_number + 1;

        let mut ctx = monad_context_with_db(std::mem::take(&mut state.db));
        ctx.block.gas_limit = BLOCK_GAS_LIMIT;
        ctx.block.basefee = 0;
        ctx.cfg.0.disable_base_fee = true;
        ctx.cfg.0.chain_id = state.chain_id;
        // Keep nonce + balance checks ON for sendRawTransaction.

        let mut evm = ctx.build_monad();
        evm.ctx().block.number = RevmU256::from(block_number);

        let tx = TxEnv::builder()
            .caller(sender)
            .kind(kind)
            .nonce(nonce)
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .value(value_revm)
            .data(revm::primitives::Bytes::copy_from_slice(&input))
            .chain_id(chain_id_opt)
            .build_fill();

        let exec_result = evm.transact_commit(tx);

        // Restore DB from EVM (always take it back whether commit succeeded or not).
        state.db = std::mem::take(evm.ctx().db_mut());

        // ── Map execution result to receipt ─────────────────────────────────
        let (status, gas_used, contract_addr) = match exec_result {
            Ok(ExecutionResult::Success { gas_used, output, .. }) => {
                let caddr = match output {
                    Output::Create(_, Some(a)) => Some(a),
                    _ => None,
                };
                (1u8, gas_used, caddr)
            }
            Ok(ExecutionResult::Revert { gas_used, .. }) => (0u8, gas_used, None),
            Ok(ExecutionResult::Halt { gas_used, .. }) => (0u8, gas_used, None),
            Err(e) => {
                // Validation error (nonce mismatch, insufficient balance, etc.) —
                // DB was already restored above, return an RPC error.
                return Err(format!("transaction validation failed: {e:?}"));
            }
        };

        // ── Advance the block and record ─────────────────────────────────────
        state.block_number = block_number;
        let block_hash = keccak256(block_number.to_le_bytes());

        let contract_addr_hex = contract_addr.map(|a| format!("0x{}", hex::encode(a.as_slice())));

        let receipt = Receipt {
            status: format!("0x{status:x}"),
            gas_used: format!("0x{gas_used:x}"),
            contract_address: contract_addr_hex,
            block_number: format!("0x{block_number:x}"),
            transaction_hash: format!("0x{}", hex::encode(tx_hash)),
            transaction_index: "0x0".to_string(),
            block_hash: format!("0x{}", hex::encode(block_hash)),
            logs: vec![],
            from: format!("0x{}", hex::encode(sender_alloy.as_slice())),
            to: to_addr.map(|a| format!("0x{}", hex::encode(a.as_slice()))),
            cumulative_gas_used: format!("0x{gas_used:x}"),
            logs_bloom: format!("0x{}", "0".repeat(512)),
            r#type: format!("0x{tx_type:x}"),
            effective_gas_price: format!("0x{gas_price:x}"),
        };

        let stored_tx = StoredTx {
            hash: format!("0x{}", hex::encode(tx_hash)),
            nonce: format!("0x{nonce:x}"),
            block_hash: format!("0x{}", hex::encode(block_hash)),
            block_number: format!("0x{block_number:x}"),
            transaction_index: "0x0".to_string(),
            from: format!("0x{}", hex::encode(sender_alloy.as_slice())),
            to: to_addr.map(|a| format!("0x{}", hex::encode(a.as_slice()))),
            value: format!("0x{value_alloy:x}"),
            gas: format!("0x{gas_limit:x}"),
            gas_price: format!("0x{gas_price:x}"),
            input: format!("0x{}", hex::encode(&input)),
            chain_id: chain_id_opt.map(|c| format!("0x{c:x}")),
            r#type: format!("0x{tx_type:x}"),
        };

        state.receipts.insert(tx_hash, receipt);
        state.transactions.insert(tx_hash, stored_tx);
        state.block_hashes.insert(block_number, block_hash);

        Ok(tx_hash)
    }

    /// Retrieve a receipt by tx hash.
    pub fn get_receipt(&self, hash: B256) -> Option<Receipt> {
        self.state.lock().unwrap().receipts.get(&hash).cloned()
    }

    /// Retrieve a stored transaction by hash.
    pub fn get_transaction(&self, hash: B256) -> Option<StoredTx> {
        self.state.lock().unwrap().transactions.get(&hash).cloned()
    }

    /// Build a minimal block stub for `eth_getBlockByNumber`.
    pub fn get_block(&self, number: u64) -> serde_json::Value {
        let state = self.state.lock().unwrap();
        let hash = state
            .block_hashes
            .get(&number)
            .copied()
            .unwrap_or_else(|| keccak256(number.to_le_bytes()));
        serde_json::json!({
            "number": format!("0x{number:x}"),
            "hash": format!("0x{}", hex::encode(hash)),
            "parentHash": format!("0x{}", "0".repeat(64)),
            "nonce": "0x0000000000000000",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "miner": "0x0000000000000000000000000000000000000000",
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x200",
            "gasLimit": format!("0x{BLOCK_GAS_LIMIT:x}"),
            "gasUsed": "0x0",
            "timestamp": "0x0",
            "transactions": [],
            "uncles": [],
            "baseFeePerGas": "0x0",
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert alloy `U256` to revm `U256` via little-endian bytes.
pub const fn alloy_u256_to_revm(v: U256) -> RevmU256 {
    RevmU256::from_le_bytes(v.to_le_bytes::<32>())
}

/// Extracted fields from a [`TxEnvelope`] for mapping to [`TxEnv`].
struct TxFields {
    nonce: u64,
    gas_limit: u64,
    /// Gas price in wei (legacy `gasPrice`; for EIP-1559 this is `maxFeePerGas`).
    gas_price: u128,
    to_alloy: Option<Address>,
    value_alloy: U256,
    input: Vec<u8>,
    tx_type: u8,
    chain_id_opt: Option<u64>,
}

/// Extract [`TxFields`] from a [`TxEnvelope`].
fn extract_tx_fields(envelope: &TxEnvelope) -> Result<TxFields, String> {
    use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};

    match envelope {
        TxEnvelope::Legacy(signed) => {
            let tx: &TxLegacy = signed.tx();
            let to = match tx.to {
                alloy_primitives::TxKind::Call(a) => Some(a),
                alloy_primitives::TxKind::Create => None,
            };
            let chain_id = tx.chain_id();
            Ok(TxFields {
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                to_alloy: to,
                value_alloy: tx.value,
                input: tx.input.to_vec(),
                tx_type: 0u8,
                chain_id_opt: chain_id,
            })
        }
        TxEnvelope::Eip2930(signed) => {
            let tx: &TxEip2930 = signed.tx();
            let to = match tx.to {
                alloy_primitives::TxKind::Call(a) => Some(a),
                alloy_primitives::TxKind::Create => None,
            };
            Ok(TxFields {
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                to_alloy: to,
                value_alloy: tx.value,
                input: tx.input.to_vec(),
                tx_type: 1u8,
                chain_id_opt: Some(tx.chain_id),
            })
        }
        TxEnvelope::Eip1559(signed) => {
            let tx: &TxEip1559 = signed.tx();
            let to = match tx.to {
                alloy_primitives::TxKind::Call(a) => Some(a),
                alloy_primitives::TxKind::Create => None,
            };
            // For 1559, charge at most max_fee_per_gas (base fee is 0 on dev node).
            Ok(TxFields {
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                to_alloy: to,
                value_alloy: tx.value,
                input: tx.input.to_vec(),
                tx_type: 2u8,
                chain_id_opt: Some(tx.chain_id),
            })
        }
        TxEnvelope::Eip4844(_) => {
            Err("blob transactions (EIP-4844) are not supported by the dev node".to_string())
        }
        _ => Err("unsupported transaction type".to_string()),
    }
}
