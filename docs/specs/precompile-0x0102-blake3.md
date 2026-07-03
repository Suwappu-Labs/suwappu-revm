# Precompile 0x0102 — BLAKE3 hash

**Address:** `0x0000000000000000000000000000000000000102`
**Gas:** `30 + 6 × ceil(len(input) / 32)`
(`SUWAPPU_BLAKE3_BASE_GAS` + `SUWAPPU_BLAKE3_WORD_GAS` per 32-byte word)
**Availability:** all Suwappu specs (registered unconditionally)
**State access:** none (pure; callable via `STATICCALL`)
**Implementation:** `suwappu_blake3_run` in
`crates/suwappu-revm/src/precompiles.rs`, using the reference
[`blake3`](https://crates.io/crates/blake3) crate.

## Input encoding

Arbitrary bytes, any length (including empty).

## Output encoding

Exactly 32 bytes: the standard, unkeyed BLAKE3-256 hash of the input.
Byte-identical to off-chain `blake3::hash` — no domain separation, no
keying, no XOF extension.

## Failure semantics

The only failure mode is out-of-gas (supplied gas below the computed
cost). Every input hashes successfully.

## Test vectors (official BLAKE3 vectors)

| Input | Output | Gas |
|-------|--------|-----|
| `""` (empty) | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` | 30 |
| `"abc"` (`0x616263`) | `6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85` | 36 |

## Gas rationale

Modeled on SHA-256's EVM pricing (base 60, word 12) and priced at half
(base 30, word 6) because BLAKE3 is substantially faster than SHA-256 in
software. Still conservative; **re-benchmark and tighten before any
production deployment** (see the doc comment on `SUWAPPU_BLAKE3_WORD_GAS`).

## Why this exists

Suwappu-DAG hashes its consensus certificate and vote pre-images with
BLAKE3. An on-chain verifier must recompute those digests before
ML-DSA-verifying the signatures, and the EVM natively exposes KECCAK256
but not BLAKE3. In the bridge, `GsxDagQuorumHeaderOracle.submitHeader`
uses this precompile to recompute the 148-byte header preimage digest:

```
BLAKE3(HEADER_DOMAIN || networkId || oracleAddr || blockNumber || stateRoot)
```

See [docs/design/pq-bridge.md](../design/pq-bridge.md) for the full layout.

## Test coverage

- Vector conformance and gas accounting: `test_blake3_precompile` in
  `precompiles.rs`.
- Digest parity with off-chain BLAKE3 through Solidity:
  `crates/suwappu-revm/tests/pq_header_oracle_e2e.rs`.
- Liveness over JSON-RPC: `cargo test -p suwappu-node` (`node_smoke`).
