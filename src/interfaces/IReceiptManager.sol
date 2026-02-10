// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReceiptCandidate, FraudProof, FinalReceipt} from "../types/GITSTypes.sol";

/// @title IReceiptManager — Receipt Candidates, Disputes, and Finalization
/// @notice Accepts receipt candidates, resolves fraud/DA disputes, finalizes receipts (Section 14.5).
interface IReceiptManager {
    /// @notice Submit a receipt candidate for a (session, epoch) pair.
    /// @dev Permissionless. Candidate carries dual signatures (ghost + shell).
    ///      B_receipt bond required. Evicted candidates get bond returned immediately.
    function submitReceiptCandidate(uint256 session_id, uint256 epoch, ReceiptCandidate calldata candidate) external payable;

    /// @notice Challenge a receipt candidate with a fraud proof (Section 10.5.4).
    /// @dev Permissionless. B_challenge bond required via msg.value.
    function challengeReceipt(uint256 session_id, uint256 epoch, FraudProof calldata proof) external payable;

    /// @notice Data availability challenge: force publication of epoch log (Section 10.5.6).
    function challengeReceiptDA(uint256 session_id, uint256 epoch, uint256 candidate_id) external payable;

    /// @notice Respond to a DA challenge by publishing the epoch log on-chain.
    /// @dev B_DA bond goes to DA responder (caller) to reimburse publication gas.
    function publishReceiptLog(uint256 session_id, uint256 epoch, uint256 candidate_id, bytes calldata encoded_log) external;

    /// @notice Resolve a timed-out DA challenge (disqualify candidate, slash bond).
    function resolveReceiptDA(uint256 session_id, uint256 epoch, uint256 candidate_id) external;

    /// @notice Finalize a receipt for a (session, epoch) pair.
    /// @dev MUST revert unless submission window closed, challenge window expired, and no pending DA.
    ///      On success: selects winning candidate, calls SessionManager.settleEpoch and
    ///      RewardsManager.recordReceipt.
    function finalizeReceipt(uint256 session_id, uint256 epoch) external;

    // ─── Views ───────────────────────────────────────────────────────────────

    function getFinalReceipt(uint256 session_id, uint256 epoch) external view returns (FinalReceipt memory);

    /// @notice O(1) count of unresolved DA challenges for a given epoch (across all sessions).
    /// @dev Used by RewardsManager to gate finalizeEpoch.
    function pendingDACount(uint256 epoch) external view returns (uint256);
}
