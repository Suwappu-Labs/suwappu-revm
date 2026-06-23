//! Smoke tests for the Suwappu dev node.
//!
//! ## What this proves
//!
//! 1. `eth_chainId` returns the configured chain ID.
//! 2. The standard dev account 0 is prefunded.
//! 3. A real signed EIP-1559 `eth_sendRawTransaction` deploys a contract; the
//!    receipt carries `contractAddress` and `status = 0x1`.
//! 4. `eth_call` returns the correct value from the deployed contract.
//! 5. **Suwappu precompiles are live**: a direct `eth_call` to `0x0102` (BLAKE3)
//!    with input `"abc"` returns the known test vector
//!    `6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85`.
//!    Plain Anvil would return `0x` (empty) because it has no 0x0102 precompile.
//!    This is the non-vacuous proof the node uses the Suwappu EVM, not vanilla.
//!
//! ## Contract deployed
//!
//! A minimal `Storage` contract that stores a constant `uint256`:
//!
//! ```solidity
//! // SPDX-License-Identifier: MIT
//! pragma solidity ^0.8.0;
//! contract Storage {
//!     uint256 public constant VALUE = 0xdeadbeef;
//!     function get() external pure returns (uint256) { return VALUE; }
//! }
//! ```
//!
//! The bytecode is hand-assembled below — no Forge dependency required.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Signature, TxKind, U256};
use alloy_rlp::Encodable;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, SigningKey};
use serde_json::Value;

// ── Node under test ──────────────────────────────────────────────────────────

// Import node modules from the binary crate via cfg(test) re-exports or just
// start the server in-process. We run the server as a background tokio task.
use suwappu_node::{node::SuwappuNode, rpc};

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// Well-known Anvil account 0 (m/44'/60'/0'/0/0 from "test test … junk").
const ACCOUNT_0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ACCOUNT_0_PRIVKEY_HEX: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Hand-assembled EVM creation bytecode for a trivial contract.
///
/// The deployed runtime ignores all calldata and always returns the ABI-encoded
/// `uint256(0xdeadbeef)` — `0x00…00deadbeef` (32 bytes).
///
/// **Constructor (12 bytes, offset 0x00):**
/// ```text
/// 60 0d  PUSH1 0x0d  -- copy 13 bytes (runtime length)
/// 60 0c  PUSH1 0x0c  -- from offset 0x0c in creation code
/// 60 00  PUSH1 0x00  -- to memory[0]
/// 39     CODECOPY
/// 60 0d  PUSH1 0x0d  -- return 13 bytes
/// 60 00  PUSH1 0x00  -- from memory[0]
/// f3     RETURN
/// ```
///
/// **Runtime (13 bytes, offset 0x0c):**
/// ```text
/// 63 de ad be ef  PUSH4 0xdeadbeef  → stack top = 0x00...00deadbeef
/// 60 00           PUSH1 0x00
/// 52              MSTORE            → mem[0..32] = 0x00...00deadbeef
/// 60 20           PUSH1 0x20
/// 60 00           PUSH1 0x00
/// f3              RETURN            → returns mem[0..32]
/// ```
const STORAGE_CREATION_HEX: &str = "600d600c600039600d6000f363deadbeef60005260206000f3";

// Helper: simple ETH JSON-RPC call via reqwest.
async fn rpc_call(port: u16, method: &str, params: Value) -> Value {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp: Value = client
        .post(format!("http://127.0.0.1:{port}"))
        .json(&body)
        .send()
        .await
        .expect("HTTP call failed")
        .json()
        .await
        .expect("JSON decode failed");
    resp
}

/// Sign an EIP-1559 transaction with the given private key and return the
/// RLP-encoded raw tx bytes ready for `eth_sendRawTransaction`.
fn sign_eip1559(
    privkey_hex: &str,
    chain_id: u64,
    nonce: u64,
    to: Option<Address>,
    value: U256,
    input: Vec<u8>,
    gas_limit: u64,
) -> Vec<u8> {
    let sk_bytes = hex::decode(privkey_hex).expect("valid privkey hex");
    let signing_key =
        SigningKey::from_bytes(sk_bytes.as_slice().into()).expect("valid k256 signing key");

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        gas_limit,
        to: match to {
            Some(a) => TxKind::Call(a),
            None => TxKind::Create,
        },
        value,
        access_list: AccessList::default(),
        input: input.into(),
    };

    // Compute the signing hash (keccak256 of the EIP-1559 signing payload).
    let hash = tx.signature_hash();

    // Sign with k256 (deterministic, no RNG).
    let (k256_sig, recid) = signing_key.sign_prehash(hash.as_slice()).expect("signing failed");
    let recovery_id: RecoveryId = recid;

    // Convert to alloy Signature.
    let sig = Signature::from_signature_and_parity(k256_sig, recovery_id.is_y_odd());

    // Wrap in TxEnvelope.
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));

    // RLP-encode.
    let mut buf = Vec::new();
    envelope.encode(&mut buf);
    buf
}

// ── Acceptance tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn smoke_test() {
    // ── Start node on an ephemeral port ─────────────────────────────────────
    let port = pick_port();
    let chain_id = 31337u64;
    let node = SuwappuNode::new(chain_id);

    {
        let node_clone = node.clone();
        tokio::spawn(async move {
            rpc::serve(node_clone, port).await;
        });
    }

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── 1. eth_chainId ───────────────────────────────────────────────────────
    let resp = rpc_call(port, "eth_chainId", serde_json::json!([])).await;
    let chain_id_hex = resp["result"].as_str().expect("result is string");
    assert_eq!(
        u64::from_str_radix(chain_id_hex.strip_prefix("0x").unwrap_or(chain_id_hex), 16)
            .expect("valid hex"),
        chain_id,
        "eth_chainId must return configured chain id"
    );

    // ── 2. Account 0 is prefunded ────────────────────────────────────────────
    let resp =
        rpc_call(port, "eth_getBalance", serde_json::json!([ACCOUNT_0_ADDR, "latest"])).await;
    let balance_hex = resp["result"].as_str().expect("balance result");
    let balance = U256::from_str_radix(balance_hex.strip_prefix("0x").unwrap_or(balance_hex), 16)
        .expect("valid hex balance");
    assert!(balance > U256::ZERO, "account 0 must have a non-zero prefunded balance");

    // ── 3. Deploy a contract ─────────────────────────────────────────────────
    let creation_bytes = hex::decode(STORAGE_CREATION_HEX).expect("valid storage bytecode hex");
    let raw_tx = sign_eip1559(
        ACCOUNT_0_PRIVKEY_HEX,
        chain_id,
        0,    // nonce 0
        None, // CREATE
        U256::ZERO,
        creation_bytes,
        500_000,
    );
    let raw_hex = format!("0x{}", hex::encode(&raw_tx));

    let resp = rpc_call(port, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(resp.get("error").is_none(), "sendRawTransaction should not return error: {resp:?}");
    let tx_hash = resp["result"].as_str().expect("tx hash result").to_string();
    assert_eq!(tx_hash.len(), 66, "tx hash must be 32 bytes hex with 0x prefix");

    // ── 4. Check receipt ─────────────────────────────────────────────────────
    let resp = rpc_call(port, "eth_getTransactionReceipt", serde_json::json!([tx_hash])).await;
    let receipt = &resp["result"];
    assert_ne!(receipt, &Value::Null, "receipt must exist for mined tx");
    assert_eq!(receipt["status"], "0x1", "deploy tx must succeed (status 0x1)");
    let contract_address =
        receipt["contractAddress"].as_str().expect("contractAddress must be set on CREATE receipt");
    assert_ne!(contract_address, "null", "contractAddress must not be null on CREATE");
    assert_eq!(
        contract_address.len(),
        42,
        "contractAddress must be a 20-byte hex address with 0x prefix"
    );

    // ── 4b. Sender recovery check — proves secp256k1 ecrecover is wired ─────
    // The receipt's `from` field must equal account 0 (the key that signed the
    // tx). A wrong recovered address would produce a different deployer and this
    // assertion would fail even with zero-gas-price and sufficient balance.
    let from_in_receipt = receipt["from"].as_str().expect("from field in receipt");
    assert_eq!(
        from_in_receipt.to_lowercase(),
        ACCOUNT_0_ADDR.to_lowercase(),
        "receipt.from must equal the signing account — proves sender recovery is correct"
    );

    // ── 5. eth_call the deployed contract ────────────────────────────────────
    // Call get() selector = 0x6d4ce63c (from keccak256("get()")[..4]).
    // Our bytecode always returns 0xdeadbeef regardless of input, so any calldata works.
    let resp = rpc_call(
        port,
        "eth_call",
        serde_json::json!([{
            "to": contract_address,
            "data": "0x6d4ce63c",
        }, "latest"]),
    )
    .await;
    assert!(resp.get("error").is_none(), "eth_call should not fail: {resp:?}");
    let output_hex = resp["result"].as_str().expect("call output");
    // The contract returns 0xdeadbeef right-shifted to fill a 32-byte word.
    // Our bytecode: PUSH4 0xdeadbeef, PUSH1 0xe0, SHL => 0xdeadbeef << 224
    // which places deadbeef in the leftmost 4 bytes.
    assert!(
        output_hex.to_lowercase().contains("deadbeef"),
        "eth_call must return 0xdeadbeef in the output; got: {output_hex}"
    );

    // ── 6. BLAKE3 precompile (0x0102) is live — the Suwappu proof ───────────
    // `eth_call` directly to address 0x0102 with input "abc" (0x616263).
    // Expected output: BLAKE3("abc") =
    //   6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
    // Vanilla Anvil returns "0x" (no 0x0102 precompile). This assertion
    // distinguishes the Suwappu node from plain Anvil.
    let resp = rpc_call(
        port,
        "eth_call",
        serde_json::json!([{
            "to": "0x0000000000000000000000000000000000000102",
            "data": "0x616263",  // "abc"
        }, "latest"]),
    )
    .await;
    // Should succeed (no error key).
    assert!(resp.get("error").is_none(), "eth_call to 0x0102 (BLAKE3) must not error: {resp:?}");
    let blake3_output = resp["result"].as_str().expect("BLAKE3 output");
    let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
    assert!(
        blake3_output.to_lowercase().contains(expected),
        "0x0102 BLAKE3(\"abc\") must equal {expected}; got {blake3_output} — \
         this confirms the Suwappu EVM (not vanilla) is running"
    );

    // ── 7. ML-DSA-65 precompile (0x0101) is live ────────────────────────────
    // Call 0x0101 with deliberately short/bad input (empty bytes). The real
    // ML-DSA precompile returns a 32-byte false word (last byte 0) for any
    // malformed input — it never panics. Vanilla Anvil returns empty `0x`
    // because it has no 0x0101 precompile at all.
    // This proves 0x0101 is registered on the node (not just inferred from
    // the MonadPrecompiles provider used in the in-process e2e tests).
    let resp = rpc_call(
        port,
        "eth_call",
        serde_json::json!([{
            "to": "0x0000000000000000000000000000000000000101",
            "data": "0x",  // empty input → malformed, but precompile still returns 32-byte false
        }, "latest"]),
    )
    .await;
    assert!(resp.get("error").is_none(), "eth_call to 0x0101 (ML-DSA-65) must not error: {resp:?}");
    let mldsa_output = resp["result"].as_str().expect("ML-DSA-65 output");
    // Must be exactly 32 bytes (64 hex chars + "0x" prefix = 66 chars).
    // Vanilla Anvil returns "0x" (2 chars). 32 bytes confirms the precompile ran.
    assert_eq!(
        mldsa_output.len(),
        66,
        "0x0101 ML-DSA-65 must return a 32-byte word for any input (even malformed); \
         got {mldsa_output} — \
         empty 0x means no precompile (vanilla Anvil); \
         32 bytes means the Suwappu precompile is live"
    );
    // Last byte must be 0 (false word — bad input, correctly rejected).
    assert!(
        mldsa_output.ends_with("00"),
        "0x0101 with bad input must return false (last byte 00), got {mldsa_output}"
    );

    println!("PASS: Suwappu dev node smoke test — all 7 checks green");
    println!("  chain_id          = {chain_id_hex}");
    println!("  account_0_balance = {balance}");
    println!("  deployed_contract = {contract_address}");
    println!("  receipt.from      = {from_in_receipt}");
    println!("  eth_call(get())   = {output_hex}");
    println!("  BLAKE3(abc)       = {blake3_output}");
    println!("  ML-DSA-65(empty)  = {mldsa_output}");
    println!("  [0x0101 ML-DSA-65 + 0x0102 BLAKE3 precompiles are LIVE]");
    println!("  [Suwappu EVM confirmed, not plain Anvil]");
}

/// Pick an OS-assigned ephemeral port.
fn pick_port() -> u16 {
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}
