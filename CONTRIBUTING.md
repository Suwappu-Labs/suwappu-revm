# Contributing to suwappu-revm

Thanks for your interest in contributing. This document covers the
practical basics; when in doubt, open an issue first and ask.

## Ground rules

- **Security-sensitive findings do not go in the issue tracker.** Follow
  [SECURITY.md](SECURITY.md).
- This crate implements **consensus-relevant execution semantics**. Changes
  to gas costs, precompile behavior, staking state transitions, or anything
  under `src/staking/`, `src/reserve_balance/`, or `src/precompiles.rs`
  need tests demonstrating the behavior and, where applicable, parity with
  the documented Monad semantics (see the README references). "It looks
  equivalent" is not enough — encode the expectation in a test.
- Keep upstream naming. Types inherited from the Monad lineage keep their
  `Monad*` names so diffs against upstream stay reviewable; only
  Suwappu-specific additions introduce new names.

## Building and testing

The toolchain is pinned via `rust-toolchain.toml` (currently Rust 1.96);
`rustup` will pick it up automatically.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check
```

CI runs exactly these checks (`.github/workflows/ci.yml`), plus the
workspace lint set in `Cargo.toml` (`missing-docs` is warn: public items
need doc comments).

Note: `suwappu-revm` depends on the ML-DSA-65 verifier from a pinned git
tag on `Suwappu-Labs/suwappu-dag`. If you cannot access that repository,
you cannot build the workspace — say so in your issue/PR and we will help.

Key test suites worth knowing:

- `crates/suwappu-revm/tests/pq_header_oracle_e2e.rs` — end-to-end proof of
  the post-quantum bridge path (real contracts, real ML-DSA-65 signatures,
  quorum accept/reject cases). If your change touches `0x0101`/`0x0102`,
  this must stay green and you should extend it for new behavior.
- `cargo test -p suwappu-node` — JSON-RPC node smoke test (deploy, call,
  precompile liveness).

## Pull requests

- Branch from `main`; keep PRs focused on one change.
- Describe *what behavior changed* and *how it is tested*, not just what
  files were touched.
- Gas-cost changes must include the benchmark or rationale for the new
  constant in the PR description.
- New public API needs doc comments (CI enforces `missing-docs` warnings).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), without any additional terms or conditions.
