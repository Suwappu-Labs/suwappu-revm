# Competitive Landscape & Gap Analysis: Tempo, Arc, Robinhood Chain

*Prepared 2026-07-03, ahead of taking `suwappu-revm` public.*

This document compares `suwappu-revm` against the three most-watched new
payments/RWA chains — **Tempo** (Stripe/Paradigm), **Arc** (Circle), and
**Robinhood Chain** — and lists the concrete gaps to close before and after
the public release. All competitor facts are sourced; self-reported vendor
benchmarks are flagged as such.

---

## 1. TL;DR

- **Two of the three competitors are REVM/Reth forks like us.** Tempo and Arc
  both build on Reth (and therefore REVM) with custom precompiles. Our
  architecture choice is validated — but it also means our differentiation
  must be sharper than "custom precompiles on REVM."
- **Arc already ships a post-quantum signature-verify precompile.** PQ verify
  alone is no longer a unique selling point. Our edge is the *specific,
  load-bearing* combination: ML-DSA-65 (FIPS 204) + BLAKE3 wired into the
  Suwappu-DAG bridge quorum (real 3-of-4 `submitHeader` flow, tested
  end-to-end over JSON-RPC).
- **The open-source bar was set by Tempo and Arc, not Robinhood.** Both opened
  their full node source *before* mainnet, with docs sites, spec processes,
  changelogs, and public testnets. Robinhood published nothing and gets away
  with it only because their moat is distribution, not technology. We are a
  technology project — we will be measured against Tempo/Arc hygiene.
- **The biggest pre-public gaps are hygiene, not features:** stale monad-revm
  branding in the README, wrong repository URL in `Cargo.toml`, no
  SECURITY.md/CONTRIBUTING.md/CHANGELOG, no per-precompile specs, no audit
  statement.

---

## 2. Landscape summaries

### 2.1 Tempo (Stripe / Paradigm) — the closest comparable

Payments-focused **L1**, mainnet live March 18, 2026. $500M Series A at $5B
valuation (Oct 2025). Permissioned validators at launch (Stripe, Visa, Zodia
among anchors), roadmap to permissionless.

- **Stack:** Reth SDK (REVM under the hood), Simplex BFT consensus via
  Commonware, ~0.5s blocks/finality, self-reported ~20k TPS testnet
  benchmarks with a public nightly performance dashboard.
- **Execution-layer surgery (deep, not cosmetic):**
  - **No native token.** `BALANCE`/`SELFBALANCE`/`CALLVALUE` always return 0;
    value moves only via the enshrined TIP-20 stablecoin standard.
    Transactions carry a `fee_token` field; fees are USD-denominated and
    payable in any USD stablecoin, converted by an enshrined fixed-rate
    **Fee AMM** to the validator's preferred token.
  - **Enshrined product precompiles:** TIP-20 tokens, stablecoin DEX,
    TIP-403 compliance policy registry ("who can send what to whom"),
    account keychain. System-only entrypoints callable only by other
    precompiles.
  - **Native account abstraction:** WebAuthn/P256 passkeys, batching,
    scheduling, protocol-level fee sponsorship, multi-key keychains — no
    ERC-4337 middleware.
  - **Blockspace partitioning:** dedicated payment lane with reserved gas so
    payments can't be starved by general EVM activity.
  - **State-growth repricing:** new storage slot 250k gas (vs 20k), code
    1,000 gas/byte (vs 200), expiring nonces.
  - **Privacy:** "Zones" — private chains anchored to Tempo (open-sourced).
- **Public footprint:** ~60 repos at github.com/tempoxyz; node is dual
  Apache-2.0/MIT, ~2,750 commits, 84 releases, active weekly; docs.tempo.xyz
  with a formal **TIP proposal process** and changelog; first-party explorer
  plus Blockscout; SDKs in Rust/Go/Python/Solidity; Machine Payments Protocol
  (MPP) HTTP standard for AI-agent payments co-developed with Stripe.
- **Caveats to cite:** validators permissioned; audits unfinished and
  unpublished; TPS figures self-reported; parallel execution unconfirmed.

Sources: docs.tempo.xyz (EVM differences, protocol, TIP-20 spec),
github.com/tempoxyz/tempo, tempo.xyz/blog/stablecoin-fees, CoinDesk
2026-03-18 mainnet coverage, Fortune Series A coverage.

### 2.2 Arc (Circle) — the closest architectural overlap

Open, EVM-compatible **L1** for stablecoin finance. Announced Aug 2025,
public testnet Oct 28, 2025 (244M+ txs by May 2026), mainnet beta targeted
"summer 2026" (not yet shipped as of early July 2026). $222M ARC presale at
$3B FDV (a16z, BlackRock, Apollo, ICE, Standard Chartered).

- **Stack:** Reth SDK / REVM execution, **Malachite BFT** consensus
  (Informal Systems team acquired), deterministic finality; self-reported
  ~3,000 TPS / <350ms finality at 20 validators. Permissioned PoA of known
  institutions, roadmap to permissioned PoS.
- **Execution-layer deltas (precompiles at `0x1800..`):**
  - **Native Coin Authority:** USDC as native gas with ERC-20 interface;
    protocol-level mint/burn/**blocklist** (issuer compliance enshrined in
    execution).
  - **CallFrom precompile:** preserves original `msg.sender` across delegated
    calls; powers Memo and Multicall3From predeploys.
  - **Fee Manager pipeline module:** EWMA-smoothed USDC base fee replacing
    EIP-1559 dynamics; ~$0.01/tx target; enterprise-predictable.
  - **PQ signature-verify precompile** — post-quantum readiness, directly
    overlapping our 0x0101.
  - Sequential execution pipeline — **no parallel EVM**; parallelism deferred
    to consensus-side multi-proposer work.
  - Opt-in confidential transfers (amount-hiding + auditor view keys) —
    designed, shipping status unconfirmed.
- **Public footprint:** `circlefin/arc-node` open (Apache-2.0) before
  mainnet, explicitly crediting Reth/REVM/Malachite; docs.arc.io; Blockscout
  as official explorer; ARC whitepaper + StableFX litepaper; 100+ testnet
  design partners (BlackRock, Goldman, Visa, Mastercard, AWS, Aave, Uniswap).
- **Caveats:** repo self-describes as "alpha software undergoing audits," no
  published audit reports found; benchmarks are Circle's own.

Sources: docs.arc.io execution-layer concepts, github.com/circlefin/arc-node,
Circle testnet press release, ARC whitepaper, CNBC presale coverage.

### 2.3 Robinhood Chain — distribution, not VM innovation

Permissionless **Ethereum L2 on stock Arbitrum Nitro** (Orbit / "Dedicated
Blockchains"), mainnet live July 1–2, 2026. Single Robinhood-run FCFS
sequencer, ~100ms soft confirms, ETH gas, blob DA, chain ID 4663, Blockscout
explorer.

- **No documented execution-layer customization at all.** Differentiation is
  contract/infra-layer: ERC-4337 AA, ERC-20 stock tokens with an on-chain
  `uiMultiplier()` (ERC-8056) for splits/dividends, per-token Chainlink
  feeds. Compliance is enforced at the issuance/redemption edge (KYB'd
  authorized participants against a Jersey issuer) plus app-layer
  jurisdiction gating — not in the VM.
- 19 stock tokens + 5 ETFs live including SPCX (SpaceX) in 120+ countries
  (not US/CA/UK/CH); tokens are legally debt/derivative instruments under
  MiFID II/MiCA, not equity.
- **No public chain repos, no published audits** — a transparency gap they
  absorb via brand and 28M-customer distribution.

Sources: docs.robinhood.com/chain, Robinhood newsroom mainnet press release,
Arbitrum blog, CoinDesk/The Block launch coverage.

---

## 3. Comparison matrix

| Dimension | Tempo | Arc | Robinhood Chain | **suwappu-revm today** |
|---|---|---|---|---|
| Execution base | Reth/REVM fork | Reth/REVM fork | Stock Arbitrum Nitro | REVM fork (Monad lineage, revm v34) |
| Status | Mainnet (Mar 2026) | Public testnet; mainnet "summer 2026" | Mainnet (Jul 2026) | Library + dev-only node |
| Consensus shipped | Simplex BFT | Malachite BFT | Nitro (single sequencer) | None in this repo (Suwappu-DAG external) |
| Gas/fee model | No native token; USD fees in any stablecoin; Fee AMM; payment lane | USDC native gas; EWMA-smoothed fees | ETH, vanilla | Monad model (higher cold costs, no refunds) |
| Custom precompiles | TIP-20, DEX, policy registry, keychain, fee AMM | USDC authority, CallFrom, fee manager, **PQ verify** | None | Staking (0x1000), reserve balance, **ML-DSA-65 (0x0101)**, **BLAKE3 (0x0102)** |
| Post-quantum | Not documented | PQ verify precompile | No | ML-DSA-65 FIPS 204, quorum-tested e2e |
| Account abstraction | Native (passkeys, sponsorship, keychains) | CallFrom + Circle Paymaster | ERC-4337 | None |
| Compliance hooks | TIP-403 policy registry | Issuer blocklist in VM | Edge/app-layer only | None |
| Privacy | Zones (open-sourced) | Confidential transfers (in progress) | None | None |
| Open source | ~60 repos, Apache/MIT, 84 releases | Full node, Apache-2.0, pre-mainnet | **Nothing** | This repo (MIT), pre-public |
| Docs/specs | Docs site + TIP process + changelog | Docs site + whitepaper + litepapers | Product docs only | Two READMEs |
| Explorer | First-party + Blockscout | Blockscout (official) | Blockscout | None |
| Audits | Ongoing, unpublished | Ongoing, unpublished | None published | None; no SECURITY.md |
| Supply chain | Public CI/releases | Public CI | n/a | **CycloneDX SBOM + Scorecard already in CI** (ahead of peers) |

---

## 4. Gap analysis

### Tier 0 — must fix before flipping the repo public

1. **Finish the rebrand.** Root `README.md` still titles itself around
   `monad-revm`: crates.io/docs.rs badges point at `monad-revm`, install
   snippets reference `category-labs/monad-revm`, and the project-layout
   section shows a `monad-revm/` tree. `Cargo.toml` `repository` points at
   `github.com/suwappu/suwappu-revm` but the org is `Suwappu-Labs`. Shipping
   this as-is undermines the launch and invites "it's just a Monad fork"
   dismissals before we can frame the lineage ourselves.
2. **State the lineage deliberately.** Tempo and Arc both credit Reth/REVM
   prominently and it reads as strength. One paragraph: "built on revm v34
   with Monad execution semantics, extended with Suwappu precompiles" — with
   a clear table of what is inherited vs. what is ours (0x0101, 0x0102,
   suwappu-node, the bridge quorum flow).
3. **SECURITY.md + audit statement.** Both Tempo and Arc say "undergoing
   audits" in-repo. We need, at minimum: a security contact, disclosure
   policy, and an honest "not yet audited; not production" banner. The
   suwappu-node README already says NOT production — mirror that at repo
   root.
4. **CONTRIBUTING.md + license clarity.** MIT is fine; the Reth ecosystem
   norm is dual MIT/Apache-2.0 (Tempo does this). Worth deciding now because
   relicensing after external contributions is painful.

### Tier 1 — credibility gaps (first weeks public)

5. **Per-precompile specifications.** Tempo publishes a TIP spec per
   enshrined feature; Arc documents each `0x1800..` precompile. We should
   publish, per precompile (0x0101, 0x0102, 0x1000, reserve balance): input
   encoding, output encoding, gas cost *and its rationale*, error behavior,
   and test vectors. Much of this exists in code comments/tests — extract it
   into `docs/specs/`.
6. **Position PQ as a system, not a primitive.** Arc has "a PQ precompile";
   we have a *working post-quantum bridge verification path*: ML-DSA-65
   quorum signatures over BLAKE3 consensus-certificate digests, exercised by
   a real 3-of-4 `submitHeader` acceptance test. Publish a short design note
   ("Post-quantum light-client bridging on EVM") — this is our headline
   differentiator and currently lives only in test code.
7. **Changelog + release discipline.** `release.yml` exists; add a
   CHANGELOG.md and tagged releases with notes. Tempo's 84 releases set the
   perceived-liveness bar.
8. **`eth_getLogs`/event support in suwappu-node.** Self-identified in the
   node README as the top limitation, and it blocks exactly the audience we
   want (bridge relayer developers watching Lock/Mint events). This is the
   highest-value single feature gap in the repo.

### Tier 2 — strategic/technical gaps (roadmap, not launch blockers)

9. **Fee/AA story.** All three competitors have an answer to "users
   shouldn't need the native token" (Tempo: stablecoin fees + sponsorship;
   Arc: USDC gas; Robinhood: 4337). We inherit Monad's model and have none.
   Decide whether Suwappu's answer is protocol-level (a sponsorship
   precompile) or ecosystem-level (4337), and say so in the roadmap even if
   unbuilt.
10. **Compliance hooks.** Tempo (TIP-403 policy registry) and Arc (issuer
    blocklist) both enshrine compliance primitives. If Suwappu targets
    payments/RWA flows over the DAG bridge, a minimal policy/allowlist
    precompile is table stakes for institutional conversations; if we target
    neutral infrastructure, document that as a deliberate stance (it is a
    positioning fork, not an omission).
11. **Public testnet + Blockscout instance.** Every one of the three uses
    Blockscout. A hosted devnet running suwappu-node (or the production node
    when ready) plus a Blockscout instance is the cheapest "it's real"
    signal available.
12. **Performance evidence.** Tempo runs a public nightly perf dashboard;
    Arc publishes (vendor) benchmarks. We should publish criterion
    benchmarks for the hot precompiles (ML-DSA-65 verify cost vs. its
    12,000 gas price; BLAKE3 vs. SHA-256 gas curves) to justify our gas
    constants publicly.

### Where we are already ahead

- **Supply-chain posture:** CycloneDX SBOM + OpenSSF Scorecard workflows are
  in CI today. Neither Tempo nor Arc surfaces SBOMs; Robinhood publishes
  nothing. Say this loudly in the README.
- **Honest limitations documentation:** the suwappu-node README's explicit
  "Limitations" section is better disclosure hygiene than most launch-stage
  projects. Keep that voice.
- **PQ + hash pairing tied to a live use case** (bridge quorum), not a
  checkbox feature.

---

## 5. Recommended sequence

1. Rebrand sweep of README/Cargo metadata (Tier 0.1–0.2) — blocks everything.
2. Add SECURITY.md, CONTRIBUTING.md, root not-production banner, license
   decision (Tier 0.3–0.4).
3. Extract precompile specs into `docs/specs/` and write the PQ-bridge
   design note (Tier 1.5–1.6).
4. CHANGELOG + first tagged public release (Tier 1.7).
5. `eth_getLogs` in suwappu-node (Tier 1.8).
6. Publish roadmap covering the Tier 2 items with explicit stances.

---

*Competitor facts compiled from public sources as of 2026-07-03; vendor
benchmarks (Tempo ~20k TPS, Arc ~3k TPS/<350ms) are self-reported and not
independently verified. Robinhood Chain launched mainnet ~48h before this
was written; details may still shift.*
