//! JSON-RPC HTTP server using axum.
//!
//! A single POST `/` endpoint dispatches all `eth_*` / `net_*` methods.
//! The request body is a JSON-RPC 2.0 object; the response is JSON-RPC 2.0.
//!
//! **Dev node only** — no authentication, no rate limiting.

use alloy_primitives::{Address, Bytes, B256, U256};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::node::SuwappuNode;

// ─── JSON-RPC request / response ────────────────────────────────────────────

/// Incoming JSON-RPC request.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// Outgoing JSON-RPC response.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// JSON-RPC error object.
#[derive(Debug, Serialize)]
pub struct RpcError {
    code: i64,
    message: String,
}

impl RpcResponse {
    const fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    fn err(id: Value, code: i64, msg: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError { code, message: msg.into() }),
        }
    }
}

// ─── Axum handler ────────────────────────────────────────────────────────────

async fn rpc_handler(
    State(node): State<SuwappuNode>,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    let id = req.id.unwrap_or(Value::Null);
    let params = req.params.unwrap_or(Value::Array(vec![]));

    let response = dispatch(&node, id, &req.method, &params);
    (StatusCode::OK, Json(response))
}

/// Dispatch a JSON-RPC method call.
fn dispatch(node: &SuwappuNode, id: Value, method: &str, params: &Value) -> RpcResponse {
    match method {
        // ── Identity ─────────────────────────────────────────────────────────
        "eth_chainId" => RpcResponse::ok(id, json!(format!("0x{:x}", node.chain_id()))),

        "net_version" => RpcResponse::ok(id, json!(node.chain_id().to_string())),

        // ── Block info ────────────────────────────────────────────────────────
        "eth_blockNumber" => RpcResponse::ok(id, json!(format!("0x{:x}", node.block_number()))),

        "eth_gasPrice" => RpcResponse::ok(id, json!("0x0")),

        "eth_maxPriorityFeePerGas" => RpcResponse::ok(id, json!("0x0")),

        // ── Account state ────────────────────────────────────────────────────
        "eth_getBalance" => {
            let addr = parse_address(params, 0);
            match addr {
                Ok(a) => {
                    let bal = node.get_balance(a);
                    RpcResponse::ok(id, json!(format!("0x{}", format_u256_hex(bal))))
                }
                Err(e) => RpcResponse::err(id, -32602, e),
            }
        }

        "eth_getTransactionCount" => {
            let addr = parse_address(params, 0);
            match addr {
                Ok(a) => RpcResponse::ok(id, json!(format!("0x{:x}", node.get_nonce(a)))),
                Err(e) => RpcResponse::err(id, -32602, e),
            }
        }

        "eth_getCode" => {
            let addr = parse_address(params, 0);
            match addr {
                Ok(a) => {
                    let code = node.get_code(a);
                    RpcResponse::ok(id, json!(format!("0x{}", hex::encode(&code))))
                }
                Err(e) => RpcResponse::err(id, -32602, e),
            }
        }

        // ── Calls ────────────────────────────────────────────────────────────
        "eth_call" => match parse_call_object(params) {
            Ok((from, to, data, value)) => match node.eth_call(from, to, data, value, None) {
                Ok(out) => RpcResponse::ok(id, json!(format!("0x{}", hex::encode(&out)))),
                Err(e) => RpcResponse::err(id, 3, e),
            },
            Err(e) => RpcResponse::err(id, -32602, e),
        },

        "eth_estimateGas" => match parse_call_object(params) {
            Ok((from, to, data, value)) => match node.estimate_gas(from, to, data, value) {
                Ok(gas) => RpcResponse::ok(id, json!(format!("0x{gas:x}"))),
                Err(e) => RpcResponse::err(id, 3, e),
            },
            Err(e) => RpcResponse::err(id, -32602, e),
        },

        // ── Transactions ─────────────────────────────────────────────────────
        "eth_sendRawTransaction" => {
            let raw_hex = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
            let raw = match decode_hex_input(raw_hex) {
                Ok(b) => b,
                Err(e) => return RpcResponse::err(id, -32602, e),
            };
            match node.send_raw_transaction(&raw) {
                Ok(hash) => RpcResponse::ok(id, json!(format!("0x{}", hex::encode(hash)))),
                Err(e) => RpcResponse::err(id, -32000, e),
            }
        }

        "eth_getTransactionReceipt" => {
            let hash = parse_hash(params, 0);
            match hash {
                Ok(h) => match node.get_receipt(h) {
                    Some(r) => RpcResponse::ok(id, serde_json::to_value(&r).unwrap_or(Value::Null)),
                    None => RpcResponse::ok(id, Value::Null),
                },
                Err(e) => RpcResponse::err(id, -32602, e),
            }
        }

        "eth_getTransactionByHash" => {
            let hash = parse_hash(params, 0);
            match hash {
                Ok(h) => match node.get_transaction(h) {
                    Some(t) => RpcResponse::ok(id, serde_json::to_value(&t).unwrap_or(Value::Null)),
                    None => RpcResponse::ok(id, Value::Null),
                },
                Err(e) => RpcResponse::err(id, -32602, e),
            }
        }

        "eth_getBlockByNumber" => {
            let block_number = parse_block_tag(params, 0, node.block_number());
            RpcResponse::ok(id, node.get_block(block_number))
        }

        // ── Logs ─────────────────────────────────────────────────────────────
        "eth_getLogs" => match parse_filter_object(params, node.block_number()) {
            Ok(filter) => {
                let logs = node.get_logs(
                    filter.from_block,
                    filter.to_block,
                    filter.block_hash,
                    &filter.addresses,
                    &filter.topics,
                );
                RpcResponse::ok(id, serde_json::to_value(&logs).unwrap_or(Value::Null))
            }
            Err(e) => RpcResponse::err(id, -32602, e),
        },

        // ── Catch-all ─────────────────────────────────────────────────────────
        other => RpcResponse::err(id, -32601, format!("method not found: {other}")),
    }
}

// ─── Parameter parsers ────────────────────────────────────────────────────────

fn parse_address(params: &Value, idx: usize) -> Result<Address, String> {
    let s = params
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing param[{idx}] (address)"))?;
    s.parse::<Address>().map_err(|e| format!("invalid address {s:?}: {e}"))
}

fn parse_hash(params: &Value, idx: usize) -> Result<B256, String> {
    let s = params
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing param[{idx}] (hash)"))?;
    parse_hash_str(s)
}

fn parse_block_tag(params: &Value, idx: usize, current: u64) -> u64 {
    let s = match params.get(idx).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return current,
    };
    match s {
        "latest" | "pending" | "safe" | "finalized" => current,
        "earliest" => 0,
        hex_str => {
            let hex_s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
            u64::from_str_radix(hex_s, 16).unwrap_or(current)
        }
    }
}

/// Parse an `eth_call`/`eth_estimateGas` transaction object.
fn parse_call_object(
    params: &Value,
) -> Result<(Option<Address>, Option<Address>, Bytes, U256), String> {
    let obj = params.get(0).ok_or("missing call object")?;

    let from = obj.get("from").and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok());

    let to = obj.get("to").and_then(|v| v.as_str()).and_then(|s| {
        if s == "0x" || s.is_empty() {
            None
        } else {
            s.parse::<Address>().ok()
        }
    });

    let data = obj
        .get("data")
        .or_else(|| obj.get("input"))
        .and_then(|v| v.as_str())
        .map(decode_hex_input)
        .transpose()?
        .map(Bytes::from)
        .unwrap_or_default();

    let value =
        obj.get("value").and_then(|v| v.as_str()).map(parse_u256_hex).unwrap_or(Ok(U256::ZERO))?;

    Ok((from, to, data, value))
}

/// Parsed `eth_getLogs` filter.
struct LogFilter {
    from_block: u64,
    to_block: u64,
    block_hash: Option<B256>,
    addresses: Vec<Address>,
    topics: Vec<Option<Vec<B256>>>,
}

/// Parse an `eth_getLogs` filter object.
fn parse_filter_object(params: &Value, current_block: u64) -> Result<LogFilter, String> {
    let obj = params.get(0).ok_or("missing filter object")?;
    if !obj.is_object() {
        return Err("filter must be an object".to_string());
    }

    let block_hash = match obj.get("blockHash").and_then(|v| v.as_str()) {
        Some(s) => Some(parse_hash_str(s)?),
        None => None,
    };
    if block_hash.is_some() && (obj.get("fromBlock").is_some() || obj.get("toBlock").is_some()) {
        return Err("blockHash is mutually exclusive with fromBlock/toBlock".to_string());
    }

    let from_block = parse_block_field(obj.get("fromBlock"), current_block);
    let to_block = parse_block_field(obj.get("toBlock"), current_block);

    let addresses = match obj.get("address") {
        None | Some(Value::Null) => vec![],
        Some(Value::String(s)) => {
            vec![s.parse::<Address>().map_err(|e| format!("invalid address {s:?}: {e}"))?]
        }
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or("address array entries must be strings")?;
                s.parse::<Address>().map_err(|e| format!("invalid address {s:?}: {e}"))
            })
            .collect::<Result<Vec<_>, String>>()?,
        Some(other) => return Err(format!("invalid address filter: {other}")),
    };

    let topics = match obj.get("topics") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(items)) => {
            if items.len() > 4 {
                return Err("topics filter has more than 4 positions".to_string());
            }
            items
                .iter()
                .map(|entry| match entry {
                    Value::Null => Ok(None),
                    Value::String(s) => Ok(Some(vec![parse_hash_str(s)?])),
                    Value::Array(alts) => alts
                        .iter()
                        .map(|v| {
                            let s = v.as_str().ok_or("topic entries must be strings")?;
                            parse_hash_str(s)
                        })
                        .collect::<Result<Vec<_>, String>>()
                        .map(Some),
                    other => Err(format!("invalid topic filter entry: {other}")),
                })
                .collect::<Result<Vec<_>, String>>()?
        }
        Some(other) => return Err(format!("invalid topics filter: {other}")),
    };

    Ok(LogFilter { from_block, to_block, block_hash, addresses, topics })
}

/// Parse a `fromBlock`/`toBlock` field value (tag or hex quantity).
fn parse_block_field(v: Option<&Value>, current: u64) -> u64 {
    let s = match v.and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return current,
    };
    match s {
        "latest" | "pending" | "safe" | "finalized" => current,
        "earliest" => 0,
        hex_str => {
            let hex_s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
            u64::from_str_radix(hex_s, 16).unwrap_or(current)
        }
    }
}

/// Parse a 32-byte hash from a hex string.
fn parse_hash_str(s: &str) -> Result<B256, String> {
    let hex_s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_s).map_err(|e| format!("invalid hash {s:?}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("hash must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(B256::from(arr))
}

fn decode_hex_input(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

fn parse_u256_hex(s: &str) -> Result<U256, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16).map_err(|e| format!("invalid U256 hex {s:?}: {e}"))
}

fn format_u256_hex(v: U256) -> String {
    format!("{v:x}")
}

// ─── Server launch ────────────────────────────────────────────────────────────

/// Start the HTTP JSON-RPC server and block forever.
pub async fn serve(node: SuwappuNode, port: u16) {
    let app = Router::new().route("/", post(rpc_handler)).with_state(node);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    println!("Suwappu dev node listening on http://0.0.0.0:{port}");
    println!("  MonadPrecompiles: 0x0101 (ML-DSA-65) + 0x0102 (BLAKE3) are LIVE");
    println!("  Prefunded dev accounts (10_000 ETH each):");
    for addr in crate::node::DEV_ACCOUNTS {
        println!("    {addr}");
    }
    println!("  THIS IS A DEV NODE. Not production.");

    axum::serve(listener, app).await.expect("server error");
}
