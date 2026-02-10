// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IRewardsManager — Epoch Emissions and Reward Distribution
/// @notice Tracks per-epoch aggregates and distributes GIT emissions (Section 14.6).
interface IRewardsManager {
    /// @notice Record a finalized receipt for reward accounting. Called by ReceiptManager.
    /// @param weight_q Q64.64 fixed-point weight for this receipt.
    function recordReceipt(
        bytes32 receipt_id,
        uint256 epoch,
        bytes32 ghost_id,
        bytes32 shell_id,
        uint32  su_delivered,
        uint256 weight_q
    ) external;

    /// @notice Finalize an epoch and compute emission distributions.
    /// @dev MUST revert if ReceiptManager.pendingDACount(epoch) > 0.
    ///      Callable after: current_epoch >= epoch + 1 + EPOCH_FINALIZATION_DELAY + FINALIZATION_GRACE.
    function finalizeEpoch(uint256 epoch) external;

    /// @notice Claim rewards for a finalized receipt.
    /// @dev Permissionless. Rewards paid to Ghost wallet and Shell payout address (looked up at claim time).
    function claimReceiptRewards(bytes32 receipt_id) external;

    /// @notice Prune storage for a finalized epoch (gas refund).
    function pruneEpoch(uint256 epoch) external;

    /// @notice Prune storage for a claimed receipt (gas refund).
    function pruneReceipt(bytes32 receipt_id) external;
}
