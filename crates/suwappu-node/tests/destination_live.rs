//! Destination-live integration test: real ML-DSA-65 quorum `submitHeader`
//! over JSON-RPC against the live `suwappu-node`.
//!
//! ## What this proves
//!
//! A live `SuwappuNode` (instant-mine, MonadPrecompiles 0x0101/0x0102) accepts a
//! real **3-of-4 ML-DSA-65 quorum** `submitHeader` sent as a signed
//! `eth_sendRawTransaction` and writes the `stateRoot`.  `eth_call
//! headerStateRoot(...)` reads it back.  A sub-quorum (1-of-4, 100 stake < 267
//! needed) reverts (receipt status `0x0`) and leaves `headerStateRoot` at zero.
//!
//! All PQ signing, digest construction, and ABI encoding is done off-chain in
//! this test (exactly as in `suwappu-revm/tests/pq_header_oracle_e2e.rs`);
//! every on-chain step goes over JSON-RPC.  There is no in-process EVM call.
//!
//! ## Self-validating design
//!
//! A wrong off-chain BLAKE3 digest would make every ML-DSA signature invalid
//! on-chain (the oracle's 0x0102 BLAKE3 recomputes the same preimage; 0x0101
//! would return false), so the accept-finalizes assertion is the runtime proof
//! that the off-chain digest, the on-chain digest, and the signatures are all
//! consistent.  An explicit `eth_call oracle.headerDigest(...)` cross-check is
//! included to surface any mismatch before `submitHeader`.
//!
//! ## Bytecode provenance
//!
//! Shared fixtures with the in-process e2e test (same Foundry-compiled creation
//! hex, same ABI).

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, U256};
use alloy_rlp::Encodable;
use alloy_sol_types::{sol, SolCall, SolValue};
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde_json::Value;

use suwappu_node::{node::SuwappuNode, rpc};

// ── Constants ────────────────────────────────────────────────────────────────

/// Well-known Anvil dev account 0.
const ACCOUNT_0_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ACCOUNT_0_PRIVKEY_HEX: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Chain ID for the dev node.
const CHAIN_ID: u64 = 31337;

/// Gas limit for contract deploys + large ML-DSA submitHeader calls.
/// Capped at 25 M — the MonadCfgEnv enforces a 30 M per-tx cap
/// (`MONAD_TX_GAS_LIMIT_CAP`), and the in-process e2e confirms 25 M is
/// sufficient for 3 ML-DSA-65 verifies + BLAKE3 + ABI overhead.
const GAS_LIMIT: u64 = 25_000_000;

/// `networkId` used for the registry + oracle + digest.  Must be consistent
/// across all three (registry constructor, oracle constructor, header digest).
const NETWORK_ID: u64 = 0x6753_7844_4147; // "gsxDAG" in big-endian

/// `keccak256("SUWAPPU_GSXDAG_HEADER_V1")` — must match the Solidity constant.
const HEADER_DOMAIN: [u8; 32] = [
    0xc7, 0x0c, 0x21, 0xeb, 0xc7, 0x9f, 0x8a, 0x20, 0x43, 0x34, 0x57, 0xa7, 0x0c, 0xf2, 0x98, 0x5f,
    0x05, 0xe7, 0x0b, 0x01, 0x7c, 0xbd, 0x95, 0xf3, 0x28, 0xe3, 0xb2, 0xa8, 0x72, 0x1e, 0xbd, 0x3a,
];

// Creation bytecode shared with the in-process e2e test.
const REGISTRY_CREATION_HEX: &str =
    include_str!("../../suwappu-revm/tests/fixtures/GsxDagValidatorRegistry.creation.hex");
const ORACLE_CREATION_HEX: &str =
    include_str!("../../suwappu-revm/tests/fixtures/GsxDagQuorumHeaderOracle.creation.hex");

// ── ABI (identical to the in-process e2e) ────────────────────────────────────

sol! {
    interface IRegistry {
        function bootstrapEpoch0(bytes32[] pkHashes, uint256[] stakes) external;
        function networkId() external view returns (uint256);
        function quorumThreshold(uint256 epoch) external view returns (uint256);
    }
    interface IOracle {
        function submitHeader(
            uint256 blockNumber,
            bytes32 stateRoot,
            uint256 epoch,
            bytes[] pubkeys,
            bytes[] sigs
        ) external;
        function headerStateRoot(uint256 chainId, uint256 blockNumber)
            external view returns (bytes32);
        function headerDigest(uint256 blockNumber, bytes32 stateRoot)
            external view returns (bytes32);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Simple JSON-RPC POST helper.
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

/// Pick an OS-assigned ephemeral port.
fn pick_port() -> u16 {
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// Sign and RLP-encode an EIP-1559 tx.  Returns the raw bytes.
fn sign_eip1559(
    privkey_hex: &str,
    chain_id: u64,
    nonce: u64,
    to: Option<Address>,
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
        value: alloy_primitives::U256::ZERO,
        access_list: AccessList::default(),
        input: input.into(),
    };

    let hash = tx.signature_hash();
    let (k256_sig, recid) = signing_key.sign_prehash(hash.as_slice()).expect("signing failed");
    let recovery_id: RecoveryId = recid;
    let sig =
        alloy_primitives::Signature::from_signature_and_parity(k256_sig, recovery_id.is_y_odd());
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));

    let mut buf = Vec::new();
    envelope.encode(&mut buf);
    buf
}

/// Send a raw tx and return the tx hash string.
async fn send_tx(port: u16, raw: &[u8]) -> String {
    let raw_hex = format!("0x{}", hex::encode(raw));
    let resp = rpc_call(port, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(resp.get("error").is_none(), "eth_sendRawTransaction returned error: {resp:?}");
    resp["result"].as_str().expect("tx hash").to_string()
}

/// Fetch receipt and return the JSON object.
async fn get_receipt(port: u16, tx_hash: &str) -> Value {
    let resp = rpc_call(port, "eth_getTransactionReceipt", serde_json::json!([tx_hash])).await;
    let r = &resp["result"];
    assert_ne!(r, &Value::Null, "receipt must exist for tx {tx_hash}");
    r.clone()
}

/// Parse a `0x`-prefixed hex address from a receipt field into `Address`.
fn parse_contract_address(receipt: &Value) -> Address {
    let s =
        receipt["contractAddress"].as_str().expect("contractAddress must be set on CREATE receipt");
    assert_ne!(s, "null", "contractAddress must not be null");
    s.parse::<Address>().expect("valid address")
}

/// `eth_call` a view function and return the raw hex result bytes.
/// Returns `None` if the node returns a JSON-RPC error (e.g. revert).
async fn eth_call_raw(port: u16, to: Address, data: Vec<u8>) -> Option<Vec<u8>> {
    let resp = rpc_call(
        port,
        "eth_call",
        serde_json::json!([{
            "to": format!("{to:#x}"),
            "data": format!("0x{}", hex::encode(&data)),
        }, "latest"]),
    )
    .await;
    if resp.get("error").is_some() {
        return None;
    }
    let hex_str = resp["result"].as_str().expect("result string");
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    Some(hex::decode(s).expect("valid hex result"))
}

/// Off-chain BLAKE3 header digest — must byte-match the oracle's on-chain
/// 0x0102 computation.
///
/// Preimage: `abi.encodePacked(HEADER_DOMAIN, networkId, oracleAddr,
/// blockNumber, stateRoot)` = 32 + 32 + 20 + 32 + 32 = 148 bytes.
fn header_digest(oracle: Address, block_number: u64, state_root: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(148);
    preimage.extend_from_slice(&HEADER_DOMAIN); // 32
    preimage.extend_from_slice(&U256::from(NETWORK_ID).to_be_bytes::<32>()); // 32
    preimage.extend_from_slice(oracle.as_slice()); // 20
    preimage.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>()); // 32
    preimage.extend_from_slice(&state_root); // 32
    assert_eq!(preimage.len(), 148, "header preimage must be exactly 148 bytes");
    *blake3::hash(&preimage).as_bytes()
}

/// One real ML-DSA-65 validator.
struct Validator {
    pk: mldsa65::PublicKey,
    sk: mldsa65::SecretKey,
}

impl Validator {
    fn gen() -> Self {
        let (pk, sk) = mldsa65::keypair();
        Self { pk, sk }
    }

    fn pubkey_bytes(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }

    fn pk_hash(&self) -> [u8; 32] {
        *keccak256(self.pubkey_bytes())
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        mldsa65::detached_sign(digest, &self.sk).as_bytes().to_vec()
    }
}

// ── The test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn destination_live() {
    // ── Start node ───────────────────────────────────────────────────────────
    let port = pick_port();
    let node = SuwappuNode::new(CHAIN_ID);
    {
        let node_clone = node.clone();
        tokio::spawn(async move {
            rpc::serve(node_clone, port).await;
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Verify chain ID ──────────────────────────────────────────────────────
    let resp = rpc_call(port, "eth_chainId", serde_json::json!([])).await;
    let cid_hex = resp["result"].as_str().expect("chainId");
    let cid = u64::from_str_radix(cid_hex.strip_prefix("0x").unwrap_or(cid_hex), 16).unwrap();
    assert_eq!(cid, CHAIN_ID, "eth_chainId");

    // Account 0 is the signer for all txs below.
    let account0: Address = ACCOUNT_0_ADDR.parse().expect("account0");

    // ── Nonce tracking (eth_getTransactionCount) ─────────────────────────────
    // We track nonces manually to avoid extra RPC round-trips.
    // Sequence: 0=registry deploy, 1=oracle deploy, 2=bootstrapEpoch0,
    //           3=accept submitHeader, 4=sub-quorum submitHeader.
    let mut nonce = 0u64;

    // ── 1. Deploy GsxDagValidatorRegistry ───────────────────────────────────
    // Constructor: (address admin, uint256 networkId)
    // admin MUST be account 0 (the tx signer); otherwise bootstrapEpoch0 reverts.
    let mut registry_ctor = hex_to_bytes(REGISTRY_CREATION_HEX);
    let ctor_args = (account0, U256::from(NETWORK_ID)).abi_encode_params();
    registry_ctor.extend_from_slice(&ctor_args);

    let raw = sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, CHAIN_ID, nonce, None, registry_ctor, GAS_LIMIT);
    let tx_hash = send_tx(port, &raw).await;
    let receipt = get_receipt(port, &tx_hash).await;
    assert_eq!(receipt["status"], "0x1", "registry deploy must succeed: {receipt:?}");
    let registry: Address = parse_contract_address(&receipt);
    nonce += 1;

    println!("Registry deployed at: {registry:#x}");

    // Sanity: registry.networkId() round-trips through the constructor immutable.
    let networkid_call = IRegistry::networkIdCall {}.abi_encode();
    let net_raw =
        eth_call_raw(port, registry, networkid_call).await.expect("networkId call must succeed");
    let net = U256::abi_decode(&net_raw).expect("decode networkId");
    assert_eq!(net, U256::from(NETWORK_ID), "constructor-set networkId mismatch");

    // ── 2. Deploy GsxDagQuorumHeaderOracle ──────────────────────────────────
    // Constructor: (address registry, uint256 gsxDagChainId)
    // gsxDagChainId == NETWORK_ID so headerStateRoot keys consistently.
    let mut oracle_ctor = hex_to_bytes(ORACLE_CREATION_HEX);
    let oracle_args = (registry, U256::from(NETWORK_ID)).abi_encode_params();
    oracle_ctor.extend_from_slice(&oracle_args);

    let raw = sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, CHAIN_ID, nonce, None, oracle_ctor, GAS_LIMIT);
    let tx_hash = send_tx(port, &raw).await;
    let receipt = get_receipt(port, &tx_hash).await;
    assert_eq!(receipt["status"], "0x1", "oracle deploy must succeed: {receipt:?}");
    let oracle: Address = parse_contract_address(&receipt);
    nonce += 1;

    println!("Oracle deployed at:   {oracle:#x}");

    // ── 3. Generate 4 real ML-DSA-65 keypairs, sort by keccak(pubkey) ────────
    let mut validators: Vec<Validator> = (0..4).map(|_| Validator::gen()).collect();
    // Sort ascending by keccak(pubkey) — the oracle's required ordering.
    validators.sort_by_key(|v| v.pk_hash());

    let pk_hashes: Vec<alloy_primitives::FixedBytes<32>> =
        validators.iter().map(|v| alloy_primitives::FixedBytes::from(v.pk_hash())).collect();
    let stakes: Vec<U256> = vec![U256::from(100u64); 4]; // equal stake: total=400, quorum=267

    // ── 4. bootstrapEpoch0 ───────────────────────────────────────────────────
    let bootstrap_data =
        IRegistry::bootstrapEpoch0Call { pkHashes: pk_hashes, stakes }.abi_encode();
    let raw = sign_eip1559(
        ACCOUNT_0_PRIVKEY_HEX,
        CHAIN_ID,
        nonce,
        Some(registry),
        bootstrap_data,
        GAS_LIMIT,
    );
    let tx_hash = send_tx(port, &raw).await;
    let receipt = get_receipt(port, &tx_hash).await;
    assert_eq!(receipt["status"], "0x1", "bootstrapEpoch0 must succeed: {receipt:?}");
    nonce += 1;

    // Verify quorum threshold: floor(400*2/3)+1 = 267.
    let threshold_call = IRegistry::quorumThresholdCall { epoch: U256::ZERO }.abi_encode();
    let thr_raw = eth_call_raw(port, registry, threshold_call)
        .await
        .expect("quorumThreshold call must succeed");
    let threshold = U256::abi_decode(&thr_raw).expect("decode threshold");
    assert_eq!(threshold, U256::from(267u64), "expected quorum threshold 267 for n=4");

    // ── 5. Build the header + off-chain digest ───────────────────────────────
    let block_number: u64 = 42;
    let state_root: [u8; 32] = [0xab; 32];
    let state_root_b256 = alloy_primitives::FixedBytes::from(state_root);

    let offchain_digest = header_digest(oracle, block_number, state_root);

    // Cross-check: eth_call oracle.headerDigest(...) must equal off-chain digest.
    // This isolates a digest mismatch from a signature failure.
    let digest_call = IOracle::headerDigestCall {
        blockNumber: U256::from(block_number),
        stateRoot: state_root_b256,
    }
    .abi_encode();
    let digest_raw =
        eth_call_raw(port, oracle, digest_call).await.expect("headerDigest eth_call must succeed");
    let onchain_digest_bytes: [u8; 32] = digest_raw.try_into().expect("32-byte digest");
    assert_eq!(
        onchain_digest_bytes, offchain_digest,
        "off-chain BLAKE3 digest must match on-chain 0x0102 digest"
    );

    // ── 6. Pre-state: headerStateRoot is zero before submitHeader ────────────
    let initial_root = read_header_state_root(port, oracle, block_number).await;
    assert_eq!(initial_root, [0u8; 32], "headerStateRoot must be zero before submitHeader");

    // ── 7. ACCEPT: 3-of-4 ML-DSA-65 submitHeader ────────────────────────────
    // Stake: 3 × 100 = 300 ≥ 267 → should finalize.
    let signers = &validators[..3]; // first 3, already sorted ascending
    let pubkeys: Vec<Bytes> = signers.iter().map(|v| Bytes::from(v.pubkey_bytes())).collect();
    let sigs: Vec<Bytes> = signers.iter().map(|v| Bytes::from(v.sign(&offchain_digest))).collect();

    let submit_data = IOracle::submitHeaderCall {
        blockNumber: U256::from(block_number),
        stateRoot: state_root_b256,
        epoch: U256::ZERO,
        pubkeys,
        sigs,
    }
    .abi_encode();

    let raw =
        sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, CHAIN_ID, nonce, Some(oracle), submit_data, GAS_LIMIT);
    let tx_hash = send_tx(port, &raw).await;
    let receipt = get_receipt(port, &tx_hash).await;

    // ── HEADLINE: real 3-of-4 ML-DSA-65 quorum finalized over JSON-RPC ──────
    assert_eq!(
        receipt["status"], "0x1",
        "submitHeader (3/4 ML-DSA-65 quorum) MUST finalize — \
         0x0101 must be present and accept genuine sigs, \
         0x0102 must match the off-chain BLAKE3 digest: {receipt:?}"
    );
    nonce += 1;

    println!("ACCEPT submitHeader tx: {tx_hash}");
    println!("  receipt.status = {}", receipt["status"]);

    // ── 8. Read-back: headerStateRoot must equal stateRoot ───────────────────
    let stored_root = read_header_state_root(port, oracle, block_number).await;
    assert_eq!(stored_root, state_root, "headerStateRoot must equal the finalized stateRoot");

    println!("  headerStateRoot({block_number}) = 0x{}", hex::encode(stored_root));
    println!("HEADLINE: real 3-of-4 ML-DSA-65 quorum submitHeader FINALIZED over JSON-RPC: YES");

    // ── 9. SUB-QUORUM: 1-of-4 submitHeader must revert ──────────────────────
    // Stake: 1 × 100 = 100 < 267 → BelowQuorum, receipt status 0x0.
    let sub_block_number: u64 = 99;
    let sub_state_root: [u8; 32] = [0xcc; 32];
    let sub_state_root_b256 = alloy_primitives::FixedBytes::from(sub_state_root);
    let sub_digest = header_digest(oracle, sub_block_number, sub_state_root);

    let sub_signers = &validators[..1]; // only 1/4
    let sub_pubkeys: Vec<Bytes> =
        sub_signers.iter().map(|v| Bytes::from(v.pubkey_bytes())).collect();
    let sub_sigs: Vec<Bytes> =
        sub_signers.iter().map(|v| Bytes::from(v.sign(&sub_digest))).collect();

    let sub_data = IOracle::submitHeaderCall {
        blockNumber: U256::from(sub_block_number),
        stateRoot: sub_state_root_b256,
        epoch: U256::ZERO,
        pubkeys: sub_pubkeys,
        sigs: sub_sigs,
    }
    .abi_encode();

    let raw =
        sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, CHAIN_ID, nonce, Some(oracle), sub_data, GAS_LIMIT);
    let sub_tx_hash = send_tx(port, &raw).await;
    let sub_receipt = get_receipt(port, &sub_tx_hash).await;

    // The node records reverts as status 0x0 (not an RPC error).
    assert_eq!(
        sub_receipt["status"], "0x0",
        "sub-quorum (1/4) submitHeader must revert (status 0x0): {sub_receipt:?}"
    );
    nonce += 1;
    // suppress unused warning
    let _ = nonce;

    println!("SUB-QUORUM submitHeader tx: {sub_tx_hash}");
    println!("  receipt.status = {} (expected 0x0 — revert)", sub_receipt["status"]);

    // sub-quorum must NOT write a state root for block 99.
    let sub_root = read_header_state_root(port, oracle, sub_block_number).await;
    assert_eq!(sub_root, [0u8; 32], "sub-quorum must not write headerStateRoot for block 99");
    println!(
        "  headerStateRoot({sub_block_number}) = 0x{} (zero — not finalized)",
        hex::encode(sub_root)
    );

    // Final summary.
    println!();
    println!("=== destination_live PASS ===");
    println!("  Registry:   {registry:#x}");
    println!("  Oracle:     {oracle:#x}");
    println!("  HEADLINE:   3-of-4 ML-DSA-65 quorum submitHeader FINALIZED over JSON-RPC: YES");
    println!("  Read-back:  headerStateRoot(42) = 0x{}", hex::encode(stored_root));
    println!("  Sub-quorum: 1-of-4 submitHeader reverted (status 0x0): YES");
    println!("  Precompiles 0x0101 (ML-DSA-65) + 0x0102 (BLAKE3) live on suwappu-node: CONFIRMED");
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Read `oracle.headerStateRoot(NETWORK_ID, blockNumber)` via `eth_call`.
/// Returns 32 zero bytes if the call fails (not finalized / no entry).
async fn read_header_state_root(port: u16, oracle: Address, block_number: u64) -> [u8; 32] {
    let call_data = IOracle::headerStateRootCall {
        chainId: U256::from(NETWORK_ID),
        blockNumber: U256::from(block_number),
    }
    .abi_encode();
    match eth_call_raw(port, oracle, call_data).await {
        Some(raw) if raw.len() == 32 => raw.try_into().expect("32 bytes"),
        Some(raw) if raw.is_empty() => [0u8; 32],
        Some(raw) => {
            // Might be ABI-encoded (32-byte padded). Decode via SolValue.
            match <alloy_primitives::FixedBytes<32> as alloy_sol_types::SolValue>::abi_decode(&raw)
            {
                Ok(v) => *v,
                Err(_) => [0u8; 32],
            }
        }
        None => [0u8; 32],
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}
