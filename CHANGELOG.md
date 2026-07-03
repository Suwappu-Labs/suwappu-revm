# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Competitive gap analysis vs Tempo, Arc, and Robinhood Chain
  (`docs/research/chain-gap-analysis.md`).
- `SECURITY.md` (private disclosure policy) and `CONTRIBUTING.md`.
- Per-precompile specifications under `docs/specs/` and the post-quantum
  bridge design note (`docs/design/pq-bridge.md`).
- `eth_getLogs` support in `suwappu-node`: receipts now carry real EVM
  logs, and log filtering by block range, address, and topics is
  implemented.

### Changed

- README rebranded to `suwappu-revm` with an explicit lineage table;
  repository metadata now points at `Suwappu-Labs/suwappu-revm`.

## [0.2.0] - 2026-07

### Added

- `suwappu-node`: development-only JSON-RPC node (anvil-style instant
  mine) with the Suwappu precompiles live, prefunded dev accounts, and a
  smoke test covering deploy/call/precompile liveness.
- `destination_live` acceptance test: real 3-of-4 ML-DSA-65 quorum
  `submitHeader` over JSON-RPC.
- Supply chain: committed CycloneDX SBOM (`sbom/suwappu-revm.cdx.json`),
  SBOM release workflow, and OpenSSF Scorecard workflow.

### Fixed

- Build from a clean checkout (dead path dependency, toolchain skew,
  missing lockfile).

## [0.1.0] - initial fork

### Added

- Monad execution semantics on revm v34: no-refund gas model, cold-access
  repricing (8,100 / 10,100), 128KB code / 256KB initcode limits,
  repriced standard precompiles, `MonadSpecId` hardforks.
- Staking precompile (`0x1000`): full read/write/syscall surface with
  linked-list pagination (`getDelegations` / `getDelegators`).
- Reserve-balance precompile (`0x1001`).
- Suwappu additions: ML-DSA-65 (FIPS 204) verify precompile (`0x0101`),
  BLAKE3 hash precompile (`0x0102`), and the `pq_header_oracle_e2e`
  bridge-verifier test.
