# Post-quantum light-client bridging on the EVM

*Design note for the Suwappu bridge destination-side verifier.*

## The problem

Cross-chain bridges that verify source-chain consensus on the destination
chain almost universally rest on classical cryptography: BLS aggregate
signatures, secp256k1 committees, or SNARKs whose soundness assumptions are
not post-quantum. A cryptographically relevant quantum computer breaks not
just future transfers but the ability to trust any header the bridge has
accepted since the attacker gained capability.

The usual "post-quantum" answers each give something up:

- **BLS aggregate on stock EVMs** — cheap and deployed everywhere, but
  classical. Not PQ.
- **Hash-based PQ proofs (STARK-wrapped verification)** — plausibly PQ, but
  as of writing there is no deployed implementation for this use case;
  proving latency and cost are open questions.
- **Scheme substitution behind a SNARK** — the SNARK itself reintroduces
  classical assumptions unless it is hash-based end to end.

Suwappu takes the direct route: **verify the lattice signatures natively in
the EVM**. No SNARK wrapper, no scheme substitution. This is the only
configuration in the Suwappu bridge's verifier matrix that is both
trust-minimized and genuinely post-quantum today.

## Construction

Two execution-layer primitives make native verification affordable:

| Address | Primitive | Spec |
|---------|-----------|------|
| `0x0101` | ML-DSA-65 verify (FIPS 204) | [spec](../specs/precompile-0x0101-mldsa65.md) |
| `0x0102` | BLAKE3-256 hash | [spec](../specs/precompile-0x0102-blake3.md) |

ML-DSA-65 is NIST security category 3, the FIPS 204 standardization of
Dilithium — a deliberate choice of the standardized, widely reviewed
parameter set over smaller or faster alternatives. BLAKE3 is required
because Suwappu-DAG hashes consensus certificate and vote pre-images with
BLAKE3, and the EVM only exposes KECCAK256 natively; the on-chain verifier
must reproduce off-chain digests byte-for-byte.

### Header attestation flow

1. **Source (Suwappu-DAG):** each validator signs a `HeaderAttestation`
   with its ML-DSA-65 key over the digest

   ```
   BLAKE3(HEADER_DOMAIN || networkId || oracleAddr || blockNumber || stateRoot)
   ```

   an exactly-148-byte `abi.encodePacked` layout:

   | Field | Type | Bytes |
   |-------|------|-------|
   | `HEADER_DOMAIN` | `bytes32` = `keccak256("SUWAPPU_GSXDAG_HEADER_V1")` | 32 |
   | `networkId` | `uint256` | 32 |
   | `oracleAddr` | `address` | 20 |
   | `blockNumber` | `uint256` | 32 |
   | `stateRoot` | `bytes32` | 32 |

   Domain separation is layered: a fixed protocol domain tag, the network
   id (constructor-set immutable), and the destination oracle's own address
   — so an attestation cannot be replayed across networks, oracle
   deployments, or protocol versions.

2. **Relay:** an off-chain relayer collects attestations until the signers'
   stake exceeds the on-chain threshold. The relayer is **liveness-trusted
   only** — it cannot forge headers, only delay them.

3. **Destination (this EVM):** the relayer calls
   `GsxDagQuorumHeaderOracle.submitHeader(blockNumber, stateRoot, epoch,
   pubkeys[], sigs[])`. The contract:
   - recomputes the 148-byte preimage digest via `0x0102`;
   - checks each supplied pubkey against the registered validator set
     (bootstrapped/rotated through `GsxDagValidatorRegistry`, keyed by
     pubkey hash) and enforces strictly-increasing signer ordering (no
     duplicate stake counting);
   - verifies each signature via `0x0101`, **dropping** (not reverting on)
     any signer whose verification returns false;
   - sums verified stake against the threshold
     `floor(totalStake × 2/3) + 1`;
   - on success writes `headerStateRoot[chainId][blockNumber] = stateRoot`
     (finalized); otherwise reverts `BelowQuorum(got, need)` and writes
     nothing.

Downstream mint/unlock/finalize logic then proves inclusion against the
finalized `stateRoot`.

### Trust model

- **Safety:** an honest >2/3-stake quorum of Suwappu-DAG validators. This
  is the same assumption as the source chain's own consensus — the bridge
  adds no new trusted parties.
- **Liveness:** the relayer (permissionless in principle; anyone holding a
  quorum of attestations can submit).
- **Cryptography:** ML-DSA-65 (FIPS 204) unforgeability and BLAKE3
  collision resistance — both believed post-quantum.

The drop-don't-revert behavior on individual bad signatures matters: a
single corrupted attestation in a batch reduces counted stake instead of
bricking the submission, so a malicious relayer cannot grief an otherwise
valid quorum by appending garbage. (Signer-ordering and membership checks
still revert, since those indicate a malformed batch.)

### Costs

Verification is linear in quorum size: one BLAKE3 digest (~60 gas for the
148-byte preimage) plus 12,000 gas per ML-DSA-65 verification, dominated by
calldata — each attestation carries a 1,952-byte pubkey and 3,309-byte
signature. For small institutional validator sets (tens of validators) this
is comfortably affordable per finalized header; it does not target
thousand-validator sets, where aggregation research (hash-based proofs)
would take over.

## Evidence this works end to end

`crates/suwappu-revm/tests/pq_header_oracle_e2e.rs` deploys the real
registry + oracle Solidity contracts inside `suwappu-revm`, generates real
ML-DSA-65 keypairs, and exercises:

- **Accept:** 3-of-4 signers (300 stake ≥ 267 threshold) → header
  finalized.
- **Tamper:** one flipped signature byte → that signer's stake dropped by
  the `0x0101` false path → `BelowQuorum(200, 267)`.
- **Sub-quorum:** 1-of-4 → `BelowQuorum(100, 267)`.

`crates/suwappu-node` additionally proves the same flow over JSON-RPC
against the dev node (`destination_live` test: real 3-of-4 quorum
`submitHeader` submitted as signed transactions).

## Known gaps / future work

- Gas constants for `0x0101`/`0x0102` are conservative estimates —
  benchmark and tighten before production (tracked in both specs).
- Validator-set rotation liveness (registry updates across epochs) is
  exercised only at bootstrap in the e2e test.
- No third-party audit yet ([SECURITY.md](../../SECURITY.md)).
