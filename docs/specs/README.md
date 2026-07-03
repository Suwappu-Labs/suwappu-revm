# Precompile registry

Every precompile registered by `MonadPrecompiles::new_with_spec` (see
`crates/suwappu-revm/src/precompiles.rs`), on top of the standard Ethereum
set for the underlying spec.

| Address | Name | Origin | Spec |
|---------|------|--------|------|
| `0x01` | ecRecover (repriced 6,000) | Monad | README, "Repriced precompiles" |
| `0x06` | ecAdd (repriced 300) | Monad | README |
| `0x07` | ecMul (repriced 30,000) | Monad | README |
| `0x08` | ecPairing (repriced 225k + 170k/pt) | Monad | README |
| `0x09` | blake2f (repriced rounds × 2) | Monad | README |
| `0x0a` | KZG point evaluation (repriced 200,000) | Monad | README |
| `0x0100` | P256VERIFY (RIP-7212 / EIP-7951, 3,450) | Ethereum ecosystem | [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951) |
| `0x0101` | ML-DSA-65 verify (FIPS 204) | **Suwappu** | [precompile-0x0101-mldsa65.md](precompile-0x0101-mldsa65.md) |
| `0x0102` | BLAKE3 hash | **Suwappu** | [precompile-0x0102-blake3.md](precompile-0x0102-blake3.md) |
| `0x1000` | Staking | Monad | README, "Staking Precompile"; canonical behavior: [Monad docs](https://docs.monad.xyz/developer-essentials/staking/staking-precompile) |
| `0x1001` | Reserve balance | Monad | README, "Reserve Balance Precompile" |

Behavioral rules that apply across the custom precompiles:

- Gas is charged before execution; if the supplied gas is below the fixed
  or computed cost, the call fails with out-of-gas (no partial output).
- The Suwappu precompiles (`0x0101`, `0x0102`) are pure functions of their
  input: no state reads, no state writes, callable via `STATICCALL`.
- The Monad state precompiles (`0x1000`, `0x1001`) accept only direct
  `CALL`; `DELEGATECALL`, `CALLCODE`, and (for both) `STATICCALL` are
  rejected — see the README sections for exact error strings.
