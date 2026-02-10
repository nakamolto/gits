// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GhostRecord, RecoveryConfig} from "../types/GITSTypes.sol";

/// @title IGhostRegistry — Ghost Identity and Recovery Configuration
/// @notice Anchors Ghost identity, checkpoint pointers, and recovery config (Section 14.2).
/// @dev ghost_id = keccak256(abi.encode(keccak256(bytes("GITS_GHOST_ID")), identity_pubkey, wallet, salt))
interface IGhostRegistry {
    // ─── Registration ────────────────────────────────────────────────────────

    /// @notice Register a new Ghost. msg.sender MUST equal `wallet`.
    /// @param ghost_id Must match keccak256(abi.encode(TAG_HASH, identity_pubkey, wallet, salt)).
    function registerGhost(
        bytes32 ghost_id,
        bytes calldata identity_pubkey,
        address wallet,
        bytes32 salt,
        RecoveryConfig calldata recoveryConfig
    ) external;

    // ─── Bond Lifecycle (passport eligibility) ───────────────────────────────

    function bondGhost(bytes32 ghost_id, address asset, uint256 amount) external;
    function beginUnbondGhost(bytes32 ghost_id, uint256 amount) external;
    function finalizeUnbondGhost(bytes32 ghost_id) external;

    /// @notice Check if a Ghost meets passport bonus eligibility for a given epoch.
    function ghostPassportEligible(bytes32 ghost_id, uint256 epoch) external view returns (bool);

    // ─── Identity Key Rotation ───────────────────────────────────────────────

    /// @notice Rotate the Ghost Identity Key.
    /// @dev Two call paths:
    ///   (a) Normal: msg.sender == wallet. proof = identity key signature over rotation digest.
    ///   (b) Recovery: msg.sender == SessionManager (via recoveryRotate). proof is empty.
    function rotateSigner(bytes32 ghost_id, bytes calldata new_identity_pubkey, bytes calldata proof) external;

    // ─── Checkpoint Management ───────────────────────────────────────────────

    /// @notice Publish a new checkpoint. msg.sender MUST equal the Ghost's wallet.
    function publishCheckpoint(
        bytes32 ghost_id,
        uint256 epoch,
        bytes32 checkpointCommitment,
        bytes32 envelopeCommitment,
        bytes calldata ptrCheckpoint,
        bytes calldata ptrEnvelope
    ) external;

    // ─── Recovery Config ─────────────────────────────────────────────────────

    /// @notice Update recovery configuration. msg.sender MUST equal the Ghost's wallet.
    function setRecoveryConfig(bytes32 ghost_id, RecoveryConfig calldata recoveryConfig) external;

    // ─── Reward History Credit ─────────────────────────────────────────────

    /// @notice Credit cumulative reward history for a Ghost. Callable ONLY by RewardsManager.
    function recordRewardCredit(bytes32 ghost_id, uint256 amount) external;

    /// @notice Cumulative reward credits for a Ghost (used for passport eligibility).
    function cumulativeRewards(bytes32 ghost_id) external view returns (uint256);

    // ─── Views ───────────────────────────────────────────────────────────────

    function getGhost(bytes32 ghost_id) external view returns (GhostRecord memory);
}
