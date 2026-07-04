// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISuwappuDagValidatorRegistry {
    function networkId() external view returns (uint256);
    function quorumThreshold(uint256 epoch) external view returns (uint256);
    function stakeAt(uint256 epoch, bytes32 pkHash) external view returns (uint256);
}

/// @notice Validator-quorum side-attestation oracle for SuwappuDag block
/// headers. Accepts a `submitHeader` call carrying real ML-DSA-65 (FIPS 204)
/// signatures over a BLAKE3 digest of the header preimage; once signed stake
/// exceeds the registry's >2/3 quorum threshold, `stateRoot` is finalized for
/// `(chainId, blockNumber)`.
///
/// This is a sync-committee-class trust model, not a consensus light client:
/// it trusts the registered validator set's honest-majority assumption.
contract SuwappuDagQuorumHeaderOracle {
    /// `keccak256("SUWAPPU_DAG_HEADER_V1")`, hard-pinned as a cross-language
    /// domain-separation tag shared with `suwappu-dag`'s Rust bridge_header
    /// module.
    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_DAG_HEADER_V1");

    address private constant MLDSA_VERIFY = address(0x0101);
    address private constant BLAKE3 = address(0x0102);

    address public immutable registry;
    uint256 public immutable chainId;

    /// chainId => blockNumber => finalized state root.
    mapping(uint256 => mapping(uint256 => bytes32)) public headerStateRoot;

    error LengthMismatch();
    error NotSorted();
    error PrecompileFailed();
    error BelowQuorum(uint256 sigStake, uint256 needed);

    constructor(address registry_, uint256 chainId_) {
        registry = registry_;
        chainId = chainId_;
    }

    /// @notice `BLAKE3(HEADER_DOMAIN || networkId || address(this) || blockNumber || stateRoot)`,
    /// the exact 148-byte `abi.encodePacked` preimage signed by validators.
    function headerDigest(uint256 blockNumber, bytes32 stateRoot) public view returns (bytes32) {
        uint256 networkId = ISuwappuDagValidatorRegistry(registry).networkId();
        bytes memory preimage =
            abi.encodePacked(HEADER_DOMAIN, networkId, address(this), blockNumber, stateRoot);
        (bool ok, bytes memory out) = BLAKE3.staticcall(preimage);
        if (!ok || out.length != 32) revert PrecompileFailed();
        return bytes32(out);
    }

    /// @param pubkeys ML-DSA-65 public keys, strictly increasing by keccak256(pubkey).
    /// @param sigs Detached ML-DSA-65 signatures over `headerDigest(blockNumber, stateRoot)`,
    /// one per entry in `pubkeys`.
    function submitHeader(
        uint256 blockNumber,
        bytes32 stateRoot,
        uint256 epoch,
        bytes[] calldata pubkeys,
        bytes[] calldata sigs
    ) external {
        if (pubkeys.length != sigs.length) revert LengthMismatch();

        bytes32 digest = headerDigest(blockNumber, stateRoot);

        uint256 sigStake = 0;
        bytes32 lastHash = bytes32(0);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes32 pkHash = keccak256(pubkeys[i]);
            if (pkHash <= lastHash) revert NotSorted();
            lastHash = pkHash;

            (bool ok, bytes memory out) =
                MLDSA_VERIFY.staticcall(abi.encodePacked(pubkeys[i], sigs[i], digest));
            if (out.length != 32) revert PrecompileFailed();

            bool valid = ok && out[31] == 0x01;
            if (valid) {
                sigStake += ISuwappuDagValidatorRegistry(registry).stakeAt(epoch, pkHash);
            }
        }

        uint256 needed = ISuwappuDagValidatorRegistry(registry).quorumThreshold(epoch);
        if (sigStake < needed) revert BelowQuorum(sigStake, needed);

        headerStateRoot[chainId][blockNumber] = stateRoot;
    }
}
