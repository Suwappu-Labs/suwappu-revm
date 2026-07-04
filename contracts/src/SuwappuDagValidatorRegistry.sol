// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Epoch-0-only validator stake registry for the SuwappuDag header
/// oracle. Bootstrapped once by `admin` with a set of ML-DSA-65 pubkey hashes
/// and their stakes; the oracle reads stakes and the >2/3 quorum threshold
/// from here.
contract SuwappuDagValidatorRegistry {
    address public immutable admin;
    uint256 public immutable networkId;

    uint256 public currentEpoch;
    bool private bootstrapped;

    mapping(uint256 => mapping(bytes32 => uint256)) private stakeByEpoch;
    mapping(uint256 => uint256) private totalStakeByEpoch;

    error NotAdmin();
    error AlreadyBootstrapped();
    error LengthMismatch();

    constructor(address admin_, uint256 networkId_) {
        admin = admin_;
        networkId = networkId_;
    }

    function bootstrapEpoch0(bytes32[] calldata pkHashes, uint256[] calldata stakes) external {
        if (msg.sender != admin) revert NotAdmin();
        if (bootstrapped) revert AlreadyBootstrapped();
        if (pkHashes.length != stakes.length) revert LengthMismatch();

        uint256 total = 0;
        for (uint256 i = 0; i < pkHashes.length; i++) {
            stakeByEpoch[0][pkHashes[i]] = stakes[i];
            total += stakes[i];
        }
        totalStakeByEpoch[0] = total;
        bootstrapped = true;
    }

    /// @notice `floor(totalStake(epoch) * 2 / 3) + 1` — strictly more than 2/3.
    function quorumThreshold(uint256 epoch) public view returns (uint256) {
        return (totalStakeByEpoch[epoch] * 2) / 3 + 1;
    }

    /// @notice Stake bonded to `pkHash` at `epoch`; 0 if unregistered.
    function stakeAt(uint256 epoch, bytes32 pkHash) external view returns (uint256) {
        return stakeByEpoch[epoch][pkHash];
    }
}
