// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SessionParams, SessionState, RBC, AuthSig, ShareReceipt} from "../types/GITSTypes.sol";

/// @title ISessionManager — Session Lifecycle, Migration, and Recovery
/// @notice Tracks session state, leases, residency, trust-refresh, migration, and recovery (Section 14.4).
interface ISessionManager {
    // ─── Session Lifecycle ───────────────────────────────────────────────────

    function openSession(bytes32 ghost_id, bytes32 shell_id, SessionParams calldata params) external;
    function renewLease(bytes32 ghost_id) external;
    function closeSession(bytes32 ghost_id) external;
    function fundNextEpoch(uint256 session_id, uint256 amount) external;

    /// @notice Called by ReceiptManager on finalized receipts to settle rent.
    function settleEpoch(uint256 session_id, uint256 epoch, uint256 su_delivered) external;

    // ─── Migration ───────────────────────────────────────────────────────────

    function startMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes32 bundle_hash) external;
    function cancelMigration(bytes32 ghost_id) external;
    function finalizeMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes calldata proof) external;

    // ─── Recovery ────────────────────────────────────────────────────────────

    /// @notice Initiate recovery. Caller MUST be a bonded Safe Haven in the Ghost's Recovery Set.
    /// @dev B_start posted via msg.value (native token). Returns monotonic attempt_id.
    function startRecovery(bytes32 ghost_id) external payable returns (uint64 attempt_id);

    /// @notice Complete recovery rotation with RBC + t-of-n Recovery Set signatures.
    function recoveryRotate(
        bytes32 ghost_id,
        uint64 attempt_id,
        bytes calldata new_identity_pubkey,
        RBC calldata rbc,
        bytes32[] calldata rs_list,
        AuthSig[] calldata sigs,
        ShareReceipt[] calldata share_receipts
    ) external;

    /// @notice Expire a stalled recovery attempt. Permissionless, timer-gated.
    function expireRecovery(bytes32 ghost_id) external;

    /// @notice Takeover a stalled recovery (after T_recovery_takeover). Permissionless.
    function takeoverRecovery(bytes32 ghost_id) external payable;

    /// @notice Exit recovery mode. Callable by GhostWallet. Requires TEC.
    function exitRecovery(bytes32 ghost_id) external;

    /// @notice Prove Safe Haven double-signing (permissionless). Triggers slashing.
    function proveSafeHavenEquivocation(
        bytes32 shell_id,
        bytes32 ghost_id,
        uint64 attempt_id,
        bytes32 checkpoint_commitment,
        bytes calldata pk_new_a,
        bytes calldata sig_a,
        bytes calldata pk_new_b,
        bytes calldata sig_b
    ) external;

    // ─── Views ───────────────────────────────────────────────────────────────

    function getSession(bytes32 ghost_id) external view returns (SessionState memory);
    function getSessionById(uint256 session_id) external view returns (SessionState memory);
    function getSessionKeys(uint256 session_id) external view returns (bytes memory ghost_key, bytes memory shell_key, address submitter);
    function effectiveTenureExpiry(bytes32 ghost_id) external view returns (uint256);
    function isRefreshAnchor(bytes32 ghost_id, bytes32 shell_id) external view returns (bool);
    function isActiveRecoveryInitiator(bytes32 shell_id) external view returns (bool);
    function processExpiry(bytes32 ghost_id) external;

    // ─── Events ──────────────────────────────────────────────────────────────

    event SessionOpened(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id);
    event SessionClosed(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id);
    event LeaseRenewed(bytes32 indexed ghost_id, uint256 new_expiry_epoch);
    event MigrationStarted(bytes32 indexed ghost_id, bytes32 indexed to_shell_id, uint256 mig_expiry_epoch);
    event MigrationFinalized(bytes32 indexed ghost_id, bytes32 indexed to_shell_id, uint256 new_session_id);
    event MigrationCancelled(bytes32 indexed ghost_id);
    event RecoveryStarted(bytes32 indexed ghost_id, uint64 attempt_id, bytes32 initiator_shell_id);
    event RecoveryRotated(bytes32 indexed ghost_id, uint64 attempt_id);
    event RecoveryExpired(bytes32 indexed ghost_id, uint64 attempt_id);
    event RecoveryExited(bytes32 indexed ghost_id);
    event ModeChanged(bytes32 indexed ghost_id, uint8 old_mode, uint8 new_mode);
    event NoAnchorsConfigured(bytes32 indexed ghost_id);
}
