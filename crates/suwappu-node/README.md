# suwappu-node

**Development-only** Ethereum JSON-RPC node backed by the Suwappu EVM.

This is *anvil with the Suwappu precompiles*: instant-mine, prefunded dev
accounts, no consensus, no p2p, no persistence. One transaction equals one
block.

**NOT production.** For local bridge integration testing only.

## What makes this different from Anvil

The EVM is built with `MonadPrecompiles::new_with_spec` (the Suwappu Monad
fork of REVM), which registers two additional precompiles that vanilla Anvil
does not have:

| Address  | Precompile       | Purpose |
|----------|------------------|---------|
| `0x0101` | ML-DSA-65 verify | FIPS 204 post-quantum signature verification (P5b) |
| `0x0102` | BLAKE3 hash      | Suwappu-DAG consensus certificate digest recomputation |

Solidity contracts that `staticcall` either of these addresses work
correctly against this node. Any Solidity that runs on the real Suwappu chain
can be deployed and tested here.

## Running

```sh
# From the repo root
cargo +1.90 run -p suwappu-node -- --port 8545 --chain-id 31337
```

Options:

| Flag         | Default | Description |
|--------------|---------|-------------|
| `--port`     | 8545    | TCP port    |
| `--chain-id` | 31337   | EVM chain ID returned by `eth_chainId` |

The Foundry / Forge toolchain, the web3 relayer, and any ethers.js / viem
client can point at `http://127.0.0.1:8545` exactly as they would at Anvil.

## Prefunded dev accounts

The 10 standard Anvil / Hardhat dev accounts (derived from the well-known
mnemonic `test test test test test test test test test test test junk`) are
each prefunded with **10 000 ETH**:

```
0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  ← account 0 (default for most tools)
0x70997970C51812dc3A010C7d01b50e0d17dc79C8
0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
0x90F79bf6EB2c4f870365E785982E1f101E93b906
0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
0x976EA74026E726554dB657fA54763abd0C3a0aa9
0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f
0xa0Ee7A142d267C1f36714E4a8F75612F20a79720
```

## Supported JSON-RPC methods

| Method | Notes |
|--------|-------|
| `eth_chainId` | Returns the configured chain ID |
| `net_version` | Same chain ID as a decimal string |
| `eth_blockNumber` | Current instant-mine block counter |
| `eth_gasPrice` | Always `0x0` (dev node, free txs) |
| `eth_maxPriorityFeePerGas` | Always `0x0` |
| `eth_getBalance` | Account balance |
| `eth_getTransactionCount` | Account nonce |
| `eth_getCode` | Deployed bytecode |
| `eth_call` | Read-only execution; no state mutation |
| `eth_estimateGas` | Sandbox execution + 20% buffer |
| `eth_sendRawTransaction` | Decode RLP, recover sender, mine 1 block |
| `eth_getTransactionReceipt` | Full receipt including `contractAddress` and emitted `logs` |
| `eth_getTransactionByHash` | Stored tx fields |
| `eth_getBlockByNumber` | Minimal stub (number, hash, timestamp, `baseFeePerGas: 0x0`) |
| `eth_getLogs` | Block range (`fromBlock`/`toBlock`), `blockHash`, `address` (single or array), positional `topics` (exact / `null` wildcard / any-of arrays) |

Blob transactions (EIP-4844) are rejected. All other EIP-1559, EIP-2930, and
legacy transactions are accepted.

## Quick verification

After starting the node, verify the Suwappu precompiles are live:

```sh
# BLAKE3("abc") should return 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000102","data":"0x616263"},"latest"],"id":1}'

# Expected: {"jsonrpc":"2.0","id":1,"result":"0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"}
# Vanilla Anvil returns "0x" (no 0x0102 precompile).
```

## Running the acceptance test

```sh
cargo +1.90 test -p suwappu-node
```

The `node_smoke` integration test:
1. Starts the node on an ephemeral port.
2. Verifies `eth_chainId` and account-0 balance.
3. Deploys a contract via a real signed EIP-1559 `eth_sendRawTransaction`.
4. Checks the receipt: `status = 0x1`, `contractAddress` set, and `from`
   equals the signing account — proving secp256k1 sender recovery works.
5. `eth_call`s the deployed contract and checks the return value.
6. Calls `0x0102` (BLAKE3) with input `"abc"` and asserts the known test
   vector — proves 0x0102 is live on the node, not just co-registered.
7. Calls `0x0101` (ML-DSA-65) with empty input and asserts a 32-byte false
   word is returned — proves 0x0101 is live on the node (vanilla Anvil
   returns empty `0x`).

## Limitations

This is a dev node. The following are known gaps vs a production node or Anvil:

- **No log subscriptions or filter objects.** `eth_getLogs` works (receipts
  carry real logs, filterable by range/address/topics), but
  `eth_newFilter`/`eth_getFilterLogs`/`eth_subscribe` do not exist — relayers
  must poll `eth_getLogs`. `logsBloom` is always zeroed; do not use it to
  skip blocks.
- **No persistence.** All state is in-process memory; restart = blank slate.
- **Single-tx blocks.** Each `eth_sendRawTransaction` mines exactly one block.
  Block-level fields like `gasUsed` on the block stub are always `0x0`.
- **No `eth_feeHistory`.**
- **No blob transactions (EIP-4844).** Rejected at the JSON-RPC layer.
- **`eth_estimateGas` is not exercised in the smoke test.** The test hardcodes
  `gas_limit = 500_000`. The estimate→sign→send loop is implemented but not
  end-to-end tested.

## Implementation note

The HTTP JSON-RPC server uses [axum](https://github.com/tokio-rs/axum) (not
`jsonrpsee`). The project task originally named `jsonrpsee` but axum was used
because it is already in the dependency graph and avoids pulling in the
`jsonrpsee` proc-macro stack. The JSON-RPC dispatch is a plain `match` in
`src/rpc.rs`. Functionally equivalent for all supported methods.
