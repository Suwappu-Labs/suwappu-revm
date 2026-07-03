# Security Policy

## Status

**This project has not undergone a third-party security audit.** It is
pre-production software. Do not use it to secure real value.

In particular:

- `suwappu-node` is a development node only (no consensus, no persistence,
  no p2p). It must never be exposed to untrusted networks or used in
  production.
- The staking precompile intentionally diverges from canonical behavior in
  documented places (e.g. `addValidator` signature verification is skipped —
  see the "Important parity note" in the README).
- Gas prices for the Suwappu precompiles (`0x0101` ML-DSA-65, `0x0102`
  BLAKE3) are set from local benchmarks and have not been adversarially
  validated.

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/Suwappu-Labs/suwappu-revm/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab).

Do **not** open a public issue for anything you believe is
security-sensitive. This includes, in this codebase especially:

- Any input that makes `0x0101` return `true` for an invalid ML-DSA-65
  signature, or `0x0102` produce a digest that differs from reference
  BLAKE3 — these break the bridge quorum's safety.
- Gas-accounting errors that allow underpriced execution of the custom
  precompiles (DoS vector).
- Staking-precompile state corruption (reward accounting, withdrawal
  windows, validator-set transitions).
- Consensus-relevant divergence from the documented Monad semantics.

We will acknowledge reports within 5 business days. Please give us a
reasonable window to ship a fix before public disclosure; we will credit
reporters in the advisory unless you prefer otherwise.

There is currently **no bug bounty program**.

## Supply chain

A CycloneDX SBOM for the full workspace is committed at
`sbom/suwappu-revm.cdx.json` and regenerated on every release
(`.github/workflows/sbom.yml`). OpenSSF Scorecard runs weekly
(`.github/workflows/scorecard.yml`). All third-party GitHub Actions are
pinned to full commit SHAs.
