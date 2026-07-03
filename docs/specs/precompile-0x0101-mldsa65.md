# Precompile 0x0101 — ML-DSA-65 signature verification (FIPS 204)

**Address:** `0x0000000000000000000000000000000000000101`
**Gas:** `12,000` (flat; `SUWAPPU_MLDSA65_VERIFY_GAS`)
**Availability:** all Suwappu specs (registered unconditionally by
`MonadPrecompiles::new_with_spec`)
**State access:** none (pure; callable via `STATICCALL`)
**Implementation:** `suwappu_mldsa65_verify_run` in
`crates/suwappu-revm/src/precompiles.rs`, delegating to
`suwappu_mldsa_precompile::verify` (pinned git tag on
`Suwappu-Labs/suwappu-dag`).

## Input encoding

Tightly packed, no ABI padding, no length prefixes:

```
input = pubkey (1,952 bytes) || signature (3,309 bytes) || message (variable)
```

| Field | Offset | Length | Notes |
|-------|--------|--------|-------|
| `pubkey` | 0 | 1,952 | ML-DSA-65 public key, FIPS 204 encoding |
| `signature` | 1,952 | 3,309 | ML-DSA-65 signature, FIPS 204 encoding |
| `message` | 5,261 | ≥ 0 | Raw message bytes (the bridge signs a 32-byte BLAKE3 digest, but any length is accepted) |

## Output encoding

Always exactly 32 bytes:

- **Valid signature:** `0x0000…0001` (last byte `1`).
- **Anything else:** `0x0000…0000` (all zeros).

## Failure semantics — never reverts on bad input

The verifier **never panics and never reverts for malformed input**. Input
shorter than 5,261 bytes, an invalid public-key encoding, an invalid
signature encoding, or a genuinely wrong signature all return the false
word. The only failure mode is out-of-gas: supplying less than 12,000 gas
fails the call with `OutOfGas` before execution.

Callers therefore MUST check the returned word; a successful call does not
mean a valid signature.

## Gas rationale

Flat 12,000. Reference points: EIP-8051 prices ML-DSA-44 verify at 4,500;
ML-DSA-65 is heavier, and the P5b design allows 8,000–12,000. We price at
the top of that band as a DoS-underpricing margin. **This constant must be
re-benchmarked and tightened before any production deployment** (see the
doc comment on `SUWAPPU_MLDSA65_VERIFY_GAS`).

## Role in the bridge

This precompile is the post-quantum trust anchor of the Suwappu bridge:
`GsxDagQuorumHeaderOracle.submitHeader` verifies each validator's ML-DSA-65
attestation over a BLAKE3 header digest (recomputed via
[`0x0102`](precompile-0x0102-blake3.md)) and finalizes the header only when
verified signers exceed the >2/3-stake threshold. See
[docs/design/pq-bridge.md](../design/pq-bridge.md).

## Test coverage

- Registration, genuine-signature accept, tampered-input reject, and gas
  accounting: `test_mldsa65_verify_precompile` in `precompiles.rs`.
- End-to-end through Solidity, including quorum accept/reject:
  `crates/suwappu-revm/tests/pq_header_oracle_e2e.rs`.
- Liveness over JSON-RPC: `cargo test -p suwappu-node` (`node_smoke`).
