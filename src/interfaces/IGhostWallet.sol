// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Policy, PolicyDelta, SessionParams} from "../types/GITSTypes.sol";

/// @title IGhostWallet — Account-Abstraction Wallet with Policy Enforcement
/// @notice User-facing entry point for all Ghost protocol actions (Section 14.3).
/// @dev Validates wallet policy then delegates to SessionManager.
///      Supports ERC-4337 for censorship-resistant renewals and meta-transactions.
interface IGhostWallet {
    // ─── Views ───────────────────────────────────────────────────────────────

    function getPolicy(bytes32 ghost_id) external view returns (Policy memory);
    function homeShell(bytes32 ghost_id) external view returns (bytes32);
    function isAllowedShell(bytes32 ghost_id, bytes32 shell_id) external view returns (bool);
    function escapeReserve(bytes32 ghost_id) external view returns (uint256 escape_gas, uint256 escape_stable);
    function hotAllowance(bytes32 ghost_id) external view returns (uint256);
    function spentThisEpoch(bytes32 ghost_id) external view returns (uint256);

    // ─── Policy Changes (tightening immediate; loosening timelocked + TEC) ───

    function proposePolicyChange(bytes32 ghost_id, PolicyDelta calldata delta) external returns (bytes32 proposal_id);
    function executePolicyChange(bytes32 ghost_id, bytes32 proposal_id) external;
    function cancelPolicyChange(bytes32 ghost_id, bytes32 proposal_id) external;

    // ─── Tightening Helpers (immediate, no timelock) ─────────────────────────

    function removeTrustedShell(bytes32 ghost_id, bytes32 shell_id) external;
    function removeAllowedShell(bytes32 ghost_id, bytes32 shell_id) external;

    // ─── Protocol Actions (validate policy, then delegate to SessionManager) ─

    function openSession(bytes32 ghost_id, bytes32 shell_id, SessionParams calldata params) external;
    function renewLease(bytes32 ghost_id) external;
    function closeSession(bytes32 ghost_id) external;
    function fundNextEpoch(bytes32 ghost_id, uint256 amount) external;
    function startMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes32 bundle_hash) external;
    function cancelMigration(bytes32 ghost_id) external;
    function finalizeMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes calldata proof) external;

    // ─── Guardian Management ─────────────────────────────────────────────────

    /// @notice Set guardian keys and quorum threshold.
    /// @dev Adding guardians / increasing t_guardian = tightening (immediate).
    ///      Removing guardians / decreasing t_guardian = loosening (timelocked + TEC).
    function setGuardians(bytes32 ghost_id, bytes[] calldata guardians, uint64 t_guardian) external;

    // ─── Recovery ────────────────────────────────────────────────────────────

    /// @notice Pay rescue bounty. Callable ONLY by SessionManager (during recoveryRotate).
    function payRescueBounty(bytes32 ghost_id, uint64 attempt_id) external;

    /// @notice Exit recovery mode. Requires TEC (homeShell, trustedShell, or AT3).
    function exitRecovery(bytes32 ghost_id) external;
}
