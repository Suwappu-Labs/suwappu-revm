// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Multisig+timelock-governed validator stake registry for the
/// SuwappuDag header oracle. Each epoch's validator set (ML-DSA-65 pubkey
/// hashes + stakes) is set via a proposal that requires `threshold`-of-`N`
/// signer approvals, followed by a mandatory `timelockDelay` before it can be
/// executed — including epoch 0 (genesis). There is no unilateral admin path:
/// a single compromised signer key can propose or approve, but can never
/// alone reach quorum or skip the delay.
///
/// Epochs are strictly sequential: epoch 0 first, then each subsequent
/// proposal must name `currentEpoch + 1`. This keeps the oracle's view of
/// "who is a validator" in sync with the chain's real validator set over
/// time, rather than frozen at a one-time bootstrap.
contract SuwappuDagValidatorRegistry {
    uint256 public immutable networkId;
    uint256 public immutable threshold;
    uint256 public immutable timelockDelay;

    address[] public signers;
    mapping(address => bool) public isSigner;

    bool public genesisSet;
    uint256 public currentEpoch;

    mapping(uint256 => mapping(bytes32 => uint256)) private stakeByEpoch;
    mapping(uint256 => uint256) private totalStakeByEpoch;

    struct Proposal {
        uint256 epoch;
        bytes32[] pkHashes;
        uint256[] stakes;
        uint256 approvalCount;
        uint256 readyAt; // 0 until `threshold` approvals reached
        bool executed;
        mapping(address => bool) approved;
    }

    mapping(bytes32 => Proposal) private proposals;
    mapping(bytes32 => bool) private proposalExists;

    error NotSigner();
    error DuplicateSigner();
    error ZeroSigner();
    error InvalidThreshold();
    error LengthMismatch();
    error EpochOutOfSequence(uint256 expected, uint256 got);
    error ProposalNotFound();
    error ProposalAlreadyExists();
    error AlreadyApproved();
    error NotApproved();
    error AlreadyExecuted();
    error TimelockNotElapsed(uint256 readyAt, uint256 nowTs);
    error QuorumNotReached();

    event ProposalCreated(bytes32 indexed proposalId, uint256 indexed epoch, address indexed proposer);
    event Approved(bytes32 indexed proposalId, address indexed signer, uint256 approvalCount);
    event Revoked(bytes32 indexed proposalId, address indexed signer, uint256 approvalCount);
    event QuorumReached(bytes32 indexed proposalId, uint256 readyAt);
    event EpochFinalized(bytes32 indexed proposalId, uint256 indexed epoch, uint256 totalStake);

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
        _;
    }

    /// @param signers_ initial signer set. Fixed at deployment — rotating
    /// signers is out of scope for this version (see contracts/README.md).
    /// @param threshold_ approvals required, 1 <= threshold_ <= signers_.length.
    /// @param networkId_ the SuwappuDag network id this registry serves.
    /// @param timelockDelay_ mandatory delay (seconds) between an epoch
    /// proposal reaching quorum and it becoming executable. Deployments MUST
    /// set this long enough for validators/monitors to notice and react to a
    /// malicious proposal before it takes effect.
    constructor(address[] memory signers_, uint256 threshold_, uint256 networkId_, uint256 timelockDelay_) {
        if (threshold_ == 0 || threshold_ > signers_.length) revert InvalidThreshold();
        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0)) revert ZeroSigner();
            if (isSigner[s]) revert DuplicateSigner();
            isSigner[s] = true;
            signers.push(s);
        }
        threshold = threshold_;
        networkId = networkId_;
        timelockDelay = timelockDelay_;
    }

    /// @notice Propose the validator set for the next epoch (or epoch 0, pre-
    /// genesis). The proposer's approval is counted immediately. Reverts if
    /// `epoch` isn't exactly the next expected epoch, or an identical
    /// proposal (same epoch + pkHashes + stakes) already exists.
    function proposeEpochTransition(uint256 epoch, bytes32[] calldata pkHashes, uint256[] calldata stakes)
        external
        onlySigner
        returns (bytes32 proposalId)
    {
        uint256 expected = genesisSet ? currentEpoch + 1 : 0;
        if (epoch != expected) revert EpochOutOfSequence(expected, epoch);
        if (pkHashes.length != stakes.length) revert LengthMismatch();

        proposalId = keccak256(abi.encode(epoch, pkHashes, stakes));
        if (proposalExists[proposalId]) revert ProposalAlreadyExists();
        proposalExists[proposalId] = true;

        Proposal storage p = proposals[proposalId];
        p.epoch = epoch;
        p.pkHashes = pkHashes;
        p.stakes = stakes;

        emit ProposalCreated(proposalId, epoch, msg.sender);
        _approve(proposalId, p);
    }

    /// @notice Approve a pending proposal. Once `threshold` approvals are
    /// reached, the timelock starts (`readyAt = now + timelockDelay`).
    function approveEpochTransition(bytes32 proposalId) external onlySigner {
        if (!proposalExists[proposalId]) revert ProposalNotFound();
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (p.approved[msg.sender]) revert AlreadyApproved();
        _approve(proposalId, p);
    }

    /// @notice Revoke a prior approval before execution. If this drops
    /// approvalCount below `threshold`, the timelock resets (readyAt = 0) —
    /// signers changing their mind blocks execution again, even if the
    /// delay had already elapsed.
    function revokeApproval(bytes32 proposalId) external onlySigner {
        if (!proposalExists[proposalId]) revert ProposalNotFound();
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (!p.approved[msg.sender]) revert NotApproved();

        p.approved[msg.sender] = false;
        p.approvalCount -= 1;
        if (p.approvalCount < threshold) {
            p.readyAt = 0;
        }
        emit Revoked(proposalId, msg.sender, p.approvalCount);
    }

    /// @notice Execute a proposal once quorum was reached and the timelock
    /// has elapsed. Permissionless — anyone may call once the conditions
    /// hold. Re-validates `epoch` is still the next expected epoch (in case
    /// another proposal for a different epoch executed first).
    function executeEpochTransition(bytes32 proposalId) external {
        if (!proposalExists[proposalId]) revert ProposalNotFound();
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (p.readyAt == 0) revert QuorumNotReached();
        if (block.timestamp < p.readyAt) revert TimelockNotElapsed(p.readyAt, block.timestamp);

        uint256 expected = genesisSet ? currentEpoch + 1 : 0;
        if (p.epoch != expected) revert EpochOutOfSequence(expected, p.epoch);

        uint256 total = 0;
        for (uint256 i = 0; i < p.pkHashes.length; i++) {
            stakeByEpoch[p.epoch][p.pkHashes[i]] = p.stakes[i];
            total += p.stakes[i];
        }
        totalStakeByEpoch[p.epoch] = total;

        currentEpoch = p.epoch;
        genesisSet = true;
        p.executed = true;

        emit EpochFinalized(proposalId, p.epoch, total);
    }

    function _approve(bytes32 proposalId, Proposal storage p) private {
        p.approved[msg.sender] = true;
        p.approvalCount += 1;
        emit Approved(proposalId, msg.sender, p.approvalCount);
        if (p.approvalCount == threshold && p.readyAt == 0) {
            p.readyAt = block.timestamp + timelockDelay;
            emit QuorumReached(proposalId, p.readyAt);
        }
    }

    /// @notice `floor(totalStake(epoch) * 2 / 3) + 1` — strictly more than 2/3.
    function quorumThreshold(uint256 epoch) public view returns (uint256) {
        return (totalStakeByEpoch[epoch] * 2) / 3 + 1;
    }

    /// @notice Stake bonded to `pkHash` at `epoch`; 0 if unregistered.
    function stakeAt(uint256 epoch, bytes32 pkHash) external view returns (uint256) {
        return stakeByEpoch[epoch][pkHash];
    }

    function signerCount() external view returns (uint256) {
        return signers.length;
    }
}
