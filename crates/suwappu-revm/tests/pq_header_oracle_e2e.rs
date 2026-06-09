//! Real post-quantum, end-to-end header-oracle finalization test.
//!
//! This is the ONE configuration that is BOTH trust-minimized AND
//! post-quantum: the `GsxDagQuorumHeaderOracle` + `GsxDagValidatorRegistry`
//! Solidity contracts run inside `suwappu-revm` (the Monad fork), and the
//! validator-quorum attestation is verified with **real ML-DSA-65 (FIPS 204)
//! signatures** via the **native 0x0101 precompile** and the header digest is
//! recomputed with **real BLAKE3** via the **native 0x0102 precompile**.
//! There are no mocks: no etched precompile stubs, no pre-baked digests, no
//! fake "valid" words. Real keypairs sign a real digest; the precompile either
//! returns `0x01` for a genuine signature or it does not.
//!
//! It is an in-process `transact_one` integration test, NOT a node/server.
//!
//! ## Why the precompile cannot be vacuously absent here
//!
//! The EVM is built with [`MonadBuilder::build_monad`], whose `MonadEvm::new`
//! installs [`MonadPrecompiles::new_with_spec`] (see
//! `crates/suwappu-revm/src/evm.rs` and `src/api/builder.rs`). That provider
//! registers 0x0101 (ML-DSA-65 verify) and 0x0102 (BLAKE3). If the harness
//! were ever mis-wired to the default `EthPrecompiles`, 0x0101 would be empty
//! -> the oracle's `staticcall` returns empty -> `out.length != 32` -> every
//! `submitHeader` reverts. The ACCEPT-FINALIZES anchor below would then fail,
//! so a green run *proves* the real precompile is present and returns `0x01`
//! for a genuine ML-DSA-65 signature. (We additionally `assert!` the provider
//! contains 0x0101/0x0102 up front, but the runtime accept path is the real
//! proof.)
//!
//! ## Bytecode provenance
//!
//! The creation bytecode in `tests/fixtures/*.creation.hex` is the Foundry
//! `bytecode.object` of the real constructors, regenerated with:
//!
//! ```sh
//! cd /Users/toma/gsx/gsx-lattice-protocol/contracts && forge build
//! # then, from contracts/out/<Name>.sol/<Name>.json, take .bytecode.object
//! # (strip the 0x prefix) into
//! # gsx-revm/crates/suwappu-revm/tests/fixtures/<Name>.creation.hex
//! ```
//!
//! We deploy via CREATE transactions that run the real constructors (NOT
//! etched runtime code), because `networkId` is a constructor-set immutable;
//! etching runtime bytecode would carry placeholder immutables.
//!
//! ## Digest provenance
//!
//! The on-chain header digest is
//! `BLAKE3(HEADER_DOMAIN || networkId || oracleAddr || blockNumber || stateRoot)`
//! with the exact `abi.encodePacked` layout (148 bytes). We replicate that
//! 148-byte layout inline (using the `blake3` crate that suwappu-revm already
//! direct-deps) rather than pulling in `gsx-consensus::bridge_header` as a
//! dev-dep: that crate inherits the gsx-dag workspace (`*.workspace = true`)
//! and pulls `gsx-crypto`, dragging the whole gsx-dag workspace into this
//! crate's build. The inline layout is self-validating: a wrong digest makes
//! the real ML-DSA verify fail, so the ACCEPT-FINALIZES anchor would not
//! finalize. `HEADER_DOMAIN` is the hard-pinned `keccak256("SUWAPPU_GSXDAG_HEADER_V1")`.

use alloy_sol_types::{sol, SolCall, SolError, SolValue};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use revm::{
    context::result::{ExecutionResult, Output},
    context::TxEnv,
    context_interface::ContextTr,
    database::InMemoryDB,
    handler::EvmTr,
    primitives::{keccak256, Address, Bytes, TxKind, B256, U256},
    state::AccountInfo,
    ExecuteCommitEvm,
};
use suwappu_revm::{
    api::{builder::MonadBuilder, default_ctx::monad_context_with_db},
    precompiles::MonadPrecompiles,
    MonadSpecId,
};

// ── ABI: only what the triad exercises ──────────────────────────────────────
sol! {
    interface IRegistry {
        function bootstrapEpoch0(bytes32[] pkHashes, uint256[] stakes) external;
        function currentEpoch() external view returns (uint256);
        function quorumThreshold(uint256 epoch) external view returns (uint256);
        function networkId() external view returns (uint256);
    }
    interface IOracle {
        function submitHeader(
            uint256 blockNumber,
            bytes32 stateRoot,
            uint256 epoch,
            bytes[] pubkeys,
            bytes[] sigs
        ) external;
        function headerStateRoot(uint256 chainId, uint256 blockNumber)
            external view returns (bytes32);
        function headerDigest(uint256 blockNumber, bytes32 stateRoot)
            external view returns (bytes32);
    }
    // For decoding the genuine revert reason in the sub-quorum case.
    error BelowQuorum(uint256 sigStake, uint256 needed);
}

const REGISTRY_CREATION_HEX: &str = include_str!("fixtures/GsxDagValidatorRegistry.creation.hex");
const ORACLE_CREATION_HEX: &str = include_str!("fixtures/GsxDagQuorumHeaderOracle.creation.hex");

// `keccak256("SUWAPPU_GSXDAG_HEADER_V1")`. Verified equal to the live keccak
// of the ASCII string in `header_domain_is_keccak` below, and matches the
// Solidity constant `GsxDagQuorumHeaderOracle.HEADER_DOMAIN`.
const HEADER_DOMAIN: [u8; 32] = [
    0xc7, 0x0c, 0x21, 0xeb, 0xc7, 0x9f, 0x8a, 0x20, 0x43, 0x34, 0x57, 0xa7, 0x0c, 0xf2, 0x98, 0x5f,
    0x05, 0xe7, 0x0b, 0x01, 0x7c, 0xbd, 0x95, 0xf3, 0x28, 0xe3, 0xb2, 0xa8, 0x72, 0x1e, 0xbd, 0x3a,
];

const NETWORK_ID: u64 = 0x6753_7844_4147; // arbitrary nonzero "gsxDAG" id
const DEPLOYER: Address = Address::new([0x11; 20]);
const GAS_LIMIT: u64 = 25_000_000;

/// A funded EVM over an in-memory DB, built with the *real* `MonadPrecompiles`
/// (0x0101 ML-DSA + 0x0102 BLAKE3), plus the deployer's tx nonce.
struct Harness {
    db: InMemoryDB,
    nonce: u64,
}

impl Harness {
    fn new() -> Self {
        // Up-front, fail-loud proof that the precompile provider we will build
        // the EVM with actually carries the native PQ precompiles. This is the
        // anti-vacuous-green guard at construction; the accept path is the
        // runtime proof.
        let pcs = MonadPrecompiles::new_with_spec(MonadSpecId::default());
        assert!(
            pcs.precompiles().contains(&revm::precompile::u64_to_address(0x0101)),
            "MonadPrecompiles must carry 0x0101 (ML-DSA-65) — not EthPrecompiles"
        );
        assert!(
            pcs.precompiles().contains(&revm::precompile::u64_to_address(0x0102)),
            "MonadPrecompiles must carry 0x0102 (BLAKE3) — not EthPrecompiles"
        );

        let mut db = InMemoryDB::default();
        db.insert_account_info(
            DEPLOYER,
            AccountInfo { balance: U256::from(u128::MAX), ..Default::default() },
        );
        Self { db, nonce: 0 }
    }

    /// Run one tx against a fresh EVM (built with `MonadPrecompiles`), commit
    /// state back into the in-memory DB, advance the deployer nonce, and return
    /// the execution result.
    fn run(&mut self, kind: TxKind, data: Vec<u8>) -> ExecutionResult {
        // `build_monad()` -> `MonadEvm::new` -> `MonadPrecompiles::new_with_spec`.
        // This is the line that makes 0x0101/0x0102 real for the call below.
        let ctx = monad_context_with_db(std::mem::take(&mut self.db));
        let mut evm = ctx.build_monad();
        evm.ctx().block.basefee = 0; // no base fee; deployer pays gas_limit * 0

        let tx = TxEnv::builder()
            .caller(DEPLOYER)
            .kind(kind)
            .nonce(self.nonce)
            .gas_limit(GAS_LIMIT)
            .gas_price(0)
            .data(Bytes::from(data))
            .build_fill();

        let out = evm.transact_commit(tx).expect("tx must reach execution (not a harness error)");
        // Pull the (mutated) DB back out of the EVM for the next tx.
        self.db = std::mem::take(evm.ctx().db_mut());
        self.nonce += 1;
        out
    }

    fn deploy(&mut self, creation_hex: &str, ctor_args: Vec<u8>) -> Address {
        let mut code = hex_to_bytes(creation_hex);
        code.extend_from_slice(&ctor_args);
        let res = self.run(TxKind::Create, code);
        match res {
            ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
            other => panic!("contract deploy failed: {other:?}"),
        }
    }

    fn call(&mut self, to: Address, data: Vec<u8>) -> ExecutionResult {
        self.run(TxKind::Call(to), data)
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// The exact 148-byte `abi.encodePacked(HEADER_DOMAIN, networkId, oracle,
/// blockNumber, stateRoot)` the oracle BLAKE3-hashes, then its BLAKE3 digest.
fn header_digest(oracle: Address, block_number: u64, state_root: B256) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(148);
    preimage.extend_from_slice(&HEADER_DOMAIN); // 32
    preimage.extend_from_slice(&U256::from(NETWORK_ID).to_be_bytes::<32>()); // uint256 networkId, 32
    preimage.extend_from_slice(oracle.as_slice()); // address, 20
    preimage.extend_from_slice(&U256::from(block_number).to_be_bytes::<32>()); // uint256 blockNumber, 32
    preimage.extend_from_slice(state_root.as_slice()); // bytes32 stateRoot, 32
    assert_eq!(preimage.len(), 148, "header preimage must be exactly 148 bytes");
    *blake3::hash(&preimage).as_bytes()
}

/// One real ML-DSA-65 validator: full pubkey bytes + secret key.
struct Validator {
    pk: mldsa65::PublicKey,
    sk: mldsa65::SecretKey,
}

impl Validator {
    fn gen() -> Self {
        let (pk, sk) = mldsa65::keypair();
        Self { pk, sk }
    }
    fn pubkey(&self) -> Vec<u8> {
        self.pk.as_bytes().to_vec()
    }
    fn pk_hash(&self) -> B256 {
        keccak256(self.pubkey())
    }
    /// Real detached ML-DSA-65 signature over the 32-byte digest.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        mldsa65::detached_sign(digest, &self.sk).as_bytes().to_vec()
    }
}

/// Deploy registry + oracle, bootstrap epoch 0 with `n` equal-stake real
/// validators, and return (harness, oracle_addr, validators) sorted by
/// keccak256(pubkey) ascending (the contract's strictly-increasing dedup order).
fn setup(n: usize) -> (Harness, Address, Vec<Validator>) {
    let mut h = Harness::new();

    // Registry(admin = DEPLOYER, networkId). DEPLOYER must be admin to bootstrap.
    let registry =
        h.deploy(REGISTRY_CREATION_HEX, (DEPLOYER, U256::from(NETWORK_ID)).abi_encode_params());
    // Oracle(registry, gsxDagChainId = NETWORK_ID). headerStateRoot keys on
    // gsxDagChainId; the digest uses registry.networkId(); keep them equal.
    let oracle =
        h.deploy(ORACLE_CREATION_HEX, (registry, U256::from(NETWORK_ID)).abi_encode_params());

    // Sanity: registry.networkId() round-trips through the real constructor.
    let r = h.call(registry, IRegistry::networkIdCall {}.abi_encode());
    let net = U256::abi_decode(r.output().expect("networkId output")).expect("decode networkId");
    assert_eq!(net, U256::from(NETWORK_ID), "constructor-set immutable networkId mismatch");

    // n real validators, sorted ascending by keccak256(pubkey).
    let mut validators: Vec<Validator> = (0..n).map(|_| Validator::gen()).collect();
    validators.sort_by_key(|v| v.pk_hash());

    let pk_hashes: Vec<B256> = validators.iter().map(|v| v.pk_hash()).collect();
    let stakes: Vec<U256> = vec![U256::from(100u64); n]; // equal stake

    let res = h.call(
        registry,
        IRegistry::bootstrapEpoch0Call { pkHashes: pk_hashes, stakes }.abi_encode(),
    );
    assert!(res.is_success(), "bootstrapEpoch0 must succeed: {res:?}");

    // Quorum threshold = floor(totalStake*2/3)+1. 4×100=400 -> 267. 3×100=300 ≥ 267.
    let r = h.call(registry, IRegistry::quorumThresholdCall { epoch: U256::ZERO }.abi_encode());
    let threshold =
        U256::abi_decode(r.output().expect("threshold output")).expect("decode threshold");
    assert_eq!(threshold, U256::from(267u64), "expected >2/3 of 400 == 267 for n=4");

    (h, oracle, validators)
}

/// Build a `submitHeader` calldata from a chosen subset of validators, with
/// pubkeys/sigs ordered by strictly-increasing keccak256(pubkey).
fn submit_header_calldata(
    oracle: Address,
    block_number: u64,
    state_root: B256,
    signers: &[&Validator],
) -> (Vec<u8>, [u8; 32]) {
    let digest = header_digest(oracle, block_number, state_root);

    // signers are taken from the already-sorted validator list, so they are
    // already in strictly-increasing keccak(pubkey) order; assert it.
    let mut last = B256::ZERO;
    for v in signers {
        assert!(v.pk_hash() > last, "signers must be strictly increasing by keccak(pubkey)");
        last = v.pk_hash();
    }

    let pubkeys: Vec<Bytes> = signers.iter().map(|v| Bytes::from(v.pubkey())).collect();
    let sigs: Vec<Bytes> = signers.iter().map(|v| Bytes::from(v.sign(&digest))).collect();

    let data = IOracle::submitHeaderCall {
        blockNumber: U256::from(block_number),
        stateRoot: state_root,
        epoch: U256::ZERO,
        pubkeys,
        sigs,
    }
    .abi_encode();
    (data, digest)
}

fn read_state_root(h: &mut Harness, oracle: Address, block_number: u64) -> B256 {
    let r = h.call(
        oracle,
        IOracle::headerStateRootCall {
            chainId: U256::from(NETWORK_ID),
            blockNumber: U256::from(block_number),
        }
        .abi_encode(),
    );
    B256::abi_decode(r.output().expect("headerStateRoot output")).expect("decode state root")
}

// ════════════════════════════════════════════════════════════════════════════
// The load-bearing triad.
// ════════════════════════════════════════════════════════════════════════════

/// ACCEPT MUST FINALIZE (the anchor). 3-of-4 REAL ML-DSA-65 sigs over the real
/// BLAKE3 digest -> submitHeader succeeds and headerStateRoot == stateRoot.
/// This single test proves: 0x0101 is present, returns 0x01 for genuine
/// ML-DSA-65 signatures, 0x0102 BLAKE3 matches our off-chain digest, and gas
/// suffices. Without it, every other result is suspect.
#[test]
fn accept_finalizes_with_real_pq_quorum() {
    let (mut h, oracle, vals) = setup(4);
    let block_number = 42u64;
    let state_root = B256::from([0xab; 32]);

    // Pre-state: not finalized.
    assert_eq!(read_state_root(&mut h, oracle, block_number), B256::ZERO);

    // Cross-check: our inline 148-byte digest equals the on-chain BLAKE3
    // (0x0102) digest. If 0x0102 were absent/wrong, this read itself reverts.
    let r = h.call(
        oracle,
        IOracle::headerDigestCall { blockNumber: U256::from(block_number), stateRoot: state_root }
            .abi_encode(),
    );
    let onchain_digest =
        B256::abi_decode(r.output().expect("headerDigest output")).expect("decode digest");
    let offchain = header_digest(oracle, block_number, state_root);
    assert_eq!(
        onchain_digest.as_slice(),
        &offchain,
        "off-chain inline digest must equal on-chain BLAKE3(0x0102) digest"
    );

    // 3 of 4 signers (already sorted) -> 300 stake ≥ 267 threshold.
    let signers: Vec<&Validator> = vals.iter().take(3).collect();
    let (data, _) = submit_header_calldata(oracle, block_number, state_root, &signers);

    let res = h.call(oracle, data);
    assert!(
        res.is_success(),
        "submitHeader with 3/4 REAL ML-DSA sigs must finalize (precompile real + gas ok): {res:?}"
    );

    // The anchor assertion.
    assert_eq!(
        read_state_root(&mut h, oracle, block_number),
        state_root,
        "headerStateRoot must equal the finalized state root"
    );
}

/// TAMPERED SIG (full quorum) must NOT finalize. Same 3-of-4 set, one signature
/// byte flipped -> the real 0x0101 returns 0x00 (reject) for that signer, its
/// stake is not counted, quorum is not met, no finalization. Isolates the
/// precompile's reject path as load-bearing.
#[test]
fn tampered_signature_does_not_finalize() {
    let (mut h, oracle, vals) = setup(4);
    let block_number = 7u64;
    let state_root = B256::from([0xcd; 32]);

    let signers: Vec<&Validator> = vals.iter().take(3).collect();
    let digest = header_digest(oracle, block_number, state_root);

    // Sign honestly, then corrupt ONE signer's signature *before* ABI-encoding,
    // by flipping a byte in the middle of its 3309-byte detached signature. This
    // guarantees the corruption is in signature data (not in any ABI
    // length/offset word), so the call cannot revert on decode framing — it
    // reaches the registry, and the real 0x0101 returns false (never panics)
    // for exactly that signer. Its keccak(pubkey) is unchanged, so the
    // strictly-increasing ordering still holds; only its stake is dropped:
    // 2×100 = 200 valid stake < 267 needed -> the genuine BelowQuorum.
    let pubkeys: Vec<Bytes> = signers.iter().map(|v| Bytes::from(v.pubkey())).collect();
    let mut sigs: Vec<Vec<u8>> = signers.iter().map(|v| v.sign(&digest)).collect();
    let mid = sigs[0].len() / 2;
    sigs[0][mid] ^= 0xff; // corrupt the first signer's signature in-place
    let sigs: Vec<Bytes> = sigs.into_iter().map(Bytes::from).collect();

    let data = IOracle::submitHeaderCall {
        blockNumber: U256::from(block_number),
        stateRoot: state_root,
        epoch: U256::ZERO,
        pubkeys,
        sigs,
    }
    .abi_encode();

    let res = h.call(oracle, data);

    // The reject must surface as the genuine BelowQuorum(200, 267): exactly one
    // signer's stake was dropped by the precompile returning 0x00. A Halt would
    // mean OOG/harness breakage; a Success would mean the reject path is dead.
    let revert_output = match &res {
        ExecutionResult::Revert { output, .. } => output.clone(),
        ExecutionResult::Halt { reason, .. } => {
            panic!("expected a BelowQuorum revert, got Halt ({reason:?}) — harness/gas problem")
        }
        ExecutionResult::Success { .. } => {
            panic!("a flipped REAL ML-DSA sig must NOT finalize")
        }
    };
    let decoded = BelowQuorum::abi_decode(&revert_output)
        .expect("tampered submission must revert with the genuine BelowQuorum");
    assert_eq!(
        decoded.sigStake,
        U256::from(200u64),
        "exactly one signer's stake (100) must be dropped by the 0x0101 reject path"
    );
    assert_eq!(decoded.needed, U256::from(267u64), ">2/3 of 400 => 267 needed");

    // And nothing was written.
    assert_eq!(
        read_state_root(&mut h, oracle, block_number),
        B256::ZERO,
        "tampered submission must not write any state root"
    );
}

/// SUB-QUORUM must revert with the genuine `BelowQuorum` reason. 1-of-4 valid
/// sigs = 100 stake (25% < 67%) -> `BelowQuorum(100, 267)`. This must be the
/// real custom-error revert — NOT OutOfGas and NOT an empty/absent-precompile
/// revert (which would mean the harness is broken, not the logic).
#[test]
fn sub_quorum_reverts_below_quorum() {
    let (mut h, oracle, vals) = setup(4);
    let block_number = 99u64;
    let state_root = B256::from([0xef; 32]);

    let signers: Vec<&Validator> = vals.iter().take(1).collect(); // only 1/4
    let (data, _) = submit_header_calldata(oracle, block_number, state_root, &signers);

    let res = h.call(oracle, data);

    let revert_output = match &res {
        ExecutionResult::Revert { output, .. } => output.clone(),
        ExecutionResult::Halt { reason, .. } => {
            panic!("expected a logic revert, got Halt ({reason:?}) — harness/gas problem, not BelowQuorum");
        }
        ExecutionResult::Success { .. } => panic!("1/4 stake must NOT finalize"),
    };

    // Decode the genuine custom-error: this distinguishes "didn't finalize
    // because of quorum logic" from a broken harness (empty precompile output
    // would surface as a different/empty revert, an OOG would be a Halt).
    let decoded = BelowQuorum::abi_decode(&revert_output)
        .expect("revert reason must be the genuine BelowQuorum(uint256,uint256)");
    assert_eq!(decoded.sigStake, U256::from(100u64), "1 validator => 100 signed stake");
    assert_eq!(decoded.needed, U256::from(267u64), ">2/3 of 400 => 267 needed");

    assert_eq!(
        read_state_root(&mut h, oracle, block_number),
        B256::ZERO,
        "sub-quorum submission must not write any state root"
    );
}

/// Guard: the hard-pinned `HEADER_DOMAIN` literal is exactly
/// `keccak256("SUWAPPU_GSXDAG_HEADER_V1")` (the Solidity constant).
#[test]
fn header_domain_is_keccak() {
    assert_eq!(keccak256(b"SUWAPPU_GSXDAG_HEADER_V1").as_slice(), &HEADER_DOMAIN);
}
