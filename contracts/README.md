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
