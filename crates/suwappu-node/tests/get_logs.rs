//! `eth_getLogs` acceptance test.
//!
//! ## What this proves
//!
//! 1. Logs emitted by a real transaction land in the transaction receipt
//!    (`logs` is no longer empty).
//! 2. `eth_getLogs` returns those logs with correct address/topics/data and
//!    block metadata.
//! 3. Filtering works: block range, `address`, positional `topics`
//!    (exact, wildcard `null`, any-of arrays), and `blockHash`.
//!
//! ## Contract deployed
//!
//! A hand-assembled "ping" contract: any call emits
//! `LOG1(topic = 0x11…11, data = uint256(0xcafebabe))` and stops.
//!
//! **Constructor (12 bytes):** copies the 47-byte runtime and returns it.
//! ```text
//! 602f600c600039602f6000f3
//! ```
//!
//! **Runtime (47 bytes):**
//! ```text
//! 63 cafebabe   PUSH4 0xcafebabe
//! 6000          PUSH1 0x00
//! 52            MSTORE            ; mem[0..32] = 0x00…cafebabe
//! 7f 11…11      PUSH32 topic      ; 32 × 0x11
//! 6020          PUSH1 0x20        ; size
//! 6000          PUSH1 0x00        ; offset
//! a1            LOG1
//! 00            STOP
//! ```

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Signature, TxKind, U256};
use alloy_rlp::Encodable;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, SigningKey};
use serde_json::{json, Value};

use suwappu_node::{node::SuwappuNode, rpc};

const ACCOUNT_0_PRIVKEY_HEX: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The LOG1 topic hard-coded in the runtime bytecode (32 × 0x11).
const TOPIC_HEX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// Creation bytecode for the ping contract described in the module docs.
const PING_CREATION_HEX: &str = concat!(
    "602f600c600039602f6000f3", // constructor
    "63cafebabe600052",         // MSTORE data
    "7f1111111111111111111111111111111111111111111111111111111111111111", // PUSH32 topic
    "60206000a100"              // LOG1; STOP
);

async fn rpc_call(port: u16, method: &str, params: Value) -> Value {
    let client = reqwest::Client::new();
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    client
        .post(format!("http://127.0.0.1:{port}"))
        .json(&body)
        .send()
        .await
        .expect("HTTP call failed")
        .json()
        .await
        .expect("JSON decode failed")
}

fn sign_eip1559(
    privkey_hex: &str,
    chain_id: u64,
    nonce: u64,
    to: Option<Address>,
    input: Vec<u8>,
) -> Vec<u8> {
    let sk_bytes = hex::decode(privkey_hex).expect("valid privkey hex");
    let signing_key =
        SigningKey::from_bytes(sk_bytes.as_slice().into()).expect("valid k256 signing key");

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        gas_limit: 500_000,
        to: match to {
            Some(a) => TxKind::Call(a),
            None => TxKind::Create,
        },
        value: U256::ZERO,
        access_list: AccessList::default(),
        input: input.into(),
    };

    let hash = tx.signature_hash();
    let (k256_sig, recid) = signing_key.sign_prehash(hash.as_slice()).expect("signing failed");
    let recovery_id: RecoveryId = recid;
    let sig = Signature::from_signature_and_parity(k256_sig, recovery_id.is_y_odd());
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));
    let mut buf = Vec::new();
    envelope.encode(&mut buf);
    buf
}

fn pick_port() -> u16 {
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// Fetch logs for the given filter object and return the result array.
async fn get_logs(port: u16, filter: Value) -> Vec<Value> {
    let resp = rpc_call(port, "eth_getLogs", json!([filter])).await;
    assert!(resp.get("error").is_none(), "eth_getLogs errored: {resp:?}");
    resp["result"].as_array().expect("eth_getLogs result must be an array").clone()
}

#[tokio::test]
async fn get_logs_end_to_end() {
    let port = pick_port();
    let chain_id = 31337u64;
    let node = SuwappuNode::new(chain_id);
    {
        let node_clone = node.clone();
        tokio::spawn(async move {
            rpc::serve(node_clone, port).await;
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Deploy the ping contract (block 1, no logs) ──────────────────────────
    let creation = hex::decode(PING_CREATION_HEX).expect("valid creation hex");
    let raw = sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, chain_id, 0, None, creation);
    let resp =
        rpc_call(port, "eth_sendRawTransaction", json!([format!("0x{}", hex::encode(&raw))])).await;
    assert!(resp.get("error").is_none(), "deploy failed: {resp:?}");
    let deploy_hash = resp["result"].as_str().expect("deploy hash").to_string();

    let resp = rpc_call(port, "eth_getTransactionReceipt", json!([deploy_hash])).await;
    let receipt = &resp["result"];
    assert_eq!(receipt["status"], "0x1", "deploy must succeed");
    let contract = receipt["contractAddress"].as_str().expect("contract address").to_string();

    // ── Call it (block 2, emits exactly one LOG1) ────────────────────────────
    let to: Address = contract.parse().expect("valid contract address");
    let raw = sign_eip1559(ACCOUNT_0_PRIVKEY_HEX, chain_id, 1, Some(to), vec![]);
    let resp =
        rpc_call(port, "eth_sendRawTransaction", json!([format!("0x{}", hex::encode(&raw))])).await;
    assert!(resp.get("error").is_none(), "ping call failed: {resp:?}");
    let ping_hash = resp["result"].as_str().expect("ping hash").to_string();

    // ── 1. Receipt carries the log ───────────────────────────────────────────
    let resp = rpc_call(port, "eth_getTransactionReceipt", json!([ping_hash])).await;
    let receipt = &resp["result"];
    assert_eq!(receipt["status"], "0x1", "ping call must succeed");
    let receipt_logs = receipt["logs"].as_array().expect("receipt logs array");
    assert_eq!(receipt_logs.len(), 1, "receipt must carry exactly one log");
    let log = &receipt_logs[0];
    assert_eq!(log["address"].as_str().unwrap().to_lowercase(), contract.to_lowercase());
    assert_eq!(log["topics"], json!([TOPIC_HEX]));
    assert_eq!(
        log["data"].as_str().unwrap(),
        format!("0x{}{}", "0".repeat(56), "cafebabe"),
        "log data must be the 32-byte word 0x00…cafebabe"
    );
    assert_eq!(log["blockNumber"], "0x2");
    assert_eq!(log["transactionHash"].as_str().unwrap(), ping_hash);
    assert_eq!(log["logIndex"], "0x0");
    let block_hash = log["blockHash"].as_str().expect("log blockHash").to_string();

    // ── 2. eth_getLogs over the full range finds it ──────────────────────────
    let logs = get_logs(port, json!({"fromBlock": "0x0", "toBlock": "latest"})).await;
    assert_eq!(logs.len(), 1, "full-range eth_getLogs must return the one log");
    assert_eq!(logs[0]["topics"], json!([TOPIC_HEX]));

    // ── 3. Block-range filtering ─────────────────────────────────────────────
    let logs = get_logs(port, json!({"fromBlock": "0x0", "toBlock": "0x1"})).await;
    assert_eq!(logs.len(), 0, "deploy block emitted no logs");
    let logs = get_logs(port, json!({"fromBlock": "0x2", "toBlock": "0x2"})).await;
    assert_eq!(logs.len(), 1);

    // ── 4. Address filtering ─────────────────────────────────────────────────
    let logs =
        get_logs(port, json!({"fromBlock": "0x0", "toBlock": "latest", "address": contract})).await;
    assert_eq!(logs.len(), 1, "filtering by the emitting address must match");
    let logs = get_logs(
        port,
        json!({
            "fromBlock": "0x0",
            "toBlock": "latest",
            "address": "0x000000000000000000000000000000000000dEaD",
        }),
    )
    .await;
    assert_eq!(logs.len(), 0, "filtering by a different address must not match");

    // ── 5. Topic filtering: exact, wildcard, any-of, mismatch ────────────────
    let logs =
        get_logs(port, json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [TOPIC_HEX]}))
            .await;
    assert_eq!(logs.len(), 1, "exact topic0 must match");
    let logs =
        get_logs(port, json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [null]})).await;
    assert_eq!(logs.len(), 1, "null topic0 is a wildcard");
    let wrong = format!("0x{}", "22".repeat(32));
    let logs = get_logs(
        port,
        json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [[wrong, TOPIC_HEX]]}),
    )
    .await;
    assert_eq!(logs.len(), 1, "any-of topic list containing the topic must match");
    let logs =
        get_logs(port, json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [wrong]})).await;
    assert_eq!(logs.len(), 0, "wrong topic0 must not match");
    let logs = get_logs(
        port,
        json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [TOPIC_HEX, TOPIC_HEX]}),
    )
    .await;
    assert_eq!(logs.len(), 0, "a topic1 constraint must not match a 1-topic log");

    // ── 6. blockHash filtering ───────────────────────────────────────────────
    let logs = get_logs(port, json!({"blockHash": block_hash})).await;
    assert_eq!(logs.len(), 1, "blockHash of the emitting block must match");
    let logs = get_logs(port, json!({"blockHash": format!("0x{}", "33".repeat(32))})).await;
    assert_eq!(logs.len(), 0, "unknown blockHash matches nothing");
    let resp =
        rpc_call(port, "eth_getLogs", json!([{"blockHash": block_hash, "fromBlock": "0x0"}])).await;
    assert!(
        resp.get("error").is_some(),
        "blockHash together with fromBlock must be rejected: {resp:?}"
    );
}
