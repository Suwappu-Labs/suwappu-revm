# suwappu-revm contracts

Solidity ground truth for the `.creation.hex` fixtures consumed by
`crates/suwappu-revm/tests/pq_header_oracle_e2e.rs` and
`crates/suwappu-node/tests/destination_live.rs`.

Previously these fixtures were checked in as opaque compiled bytecode with no
source in this repo (the source was believed to live in
`suwappu-lattice-protocol/contracts`, but no longer does — that provenance
comment had gone stale). This directory restores a reproducible source of
truth.

## Regenerating the fixtures

```sh
forge build
python3 - <<'EOF'
import json
for name in ["SuwappuDagValidatorRegistry", "SuwappuDagQuorumHeaderOracle"]:
    with open(f"out/{name}.sol/{name}.json") as f:
        data = json.load(f)
    obj = data["bytecode"]["object"]
    hexstr = obj[2:] if obj.startswith("0x") else obj
    with open(f"../crates/suwappu-revm/tests/fixtures/{name}.creation.hex", "w") as f:
        f.write(hexstr)
EOF
```

`HEADER_DOMAIN` in `SuwappuDagQuorumHeaderOracle.sol` (`keccak256("SUWAPPU_DAG_HEADER_V1")`)
must stay byte-identical to the same-named constant in `suwappu-dag`'s Rust
`crates/suwappu-consensus/src/bridge_header.rs` — that cross-repo agreement is
NOT enforced by any CI check today, only by the hard-coded constants on both
sides.

## `SuwappuDagValidatorRegistry` governance

The registry has no unilateral admin path. Each epoch's validator set is set by a
multisig+timelock flow:

1. Any signer calls `proposeEpochTransition(epoch, pkHashes, stakes)` — `epoch` must be
   `0` (genesis) or `currentEpoch + 1` (strictly sequential). The proposer is
   auto-approved.
2. Other signers call `approveEpochTransition(proposalId)` until `threshold` approvals
   are reached, at which point `readyAt = block.timestamp + timelockDelay` is set.
3. Anyone may call `executeEpochTransition(proposalId)` once `block.timestamp >=
   readyAt`. A signer can `revokeApproval` before execution; if that drops the count
   below `threshold`, the timelock resets.

A single compromised signer key can propose or approve, but can never alone reach
quorum or skip the delay — deployments should set `timelockDelay` long enough for
validators/monitors to notice and react to a malicious proposal before it lands.

Constructor: `(address[] signers, uint256 threshold, uint256 networkId, uint256
timelockDelay)`. The signer set is fixed at deployment; rotating signers is out of
scope for this version.
