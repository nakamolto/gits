// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ShellRecord} from "../types/GITSTypes.sol";

/// @title IShellRegistry — Shell Identity and Bond Management
/// @notice On-chain registry for Shell identity, bonds, certificates, and assurance tiers (Section 14.1).
/// @dev shell_id = keccak256(abi.encode(keccak256(bytes("GITS_SHELL_ID")), identity_pubkey, salt))
interface IShellRegistry {
    // ─── Registration ────────────────────────────────────────────────────────

    /// @notice Register a new Shell with identity, bond, and optional certificate.
    /// @param shell_id Must match keccak256(abi.encode(TAG_HASH, identity_pubkey, salt)).
    /// @param sig Identity key signature over registration digest (anti-frontrunning).
    function registerShell(
        bytes32 shell_id,
        bytes calldata identity_pubkey,
        bytes calldata offer_signer_pubkey,
        address payout_address,
        bytes32 salt,
        address bond_asset,
        uint256 bond_amount,
        bytes calldata cert,
        bytes[] calldata sigs_cert,
        bytes calldata sig
    ) external;

    // ─── Key Management (two-step propose/confirm, timelocked) ───────────────

    function proposeIdentityKeyUpdate(bytes32 shell_id, bytes calldata new_identity_pubkey, bytes calldata proof) external;
    function confirmIdentityKeyUpdate(bytes32 shell_id) external;

    function proposeOfferSignerUpdate(bytes32 shell_id, bytes calldata new_offer_signer_pubkey) external;
    function confirmOfferSignerUpdate(bytes32 shell_id) external;

    function proposeRecoveryKeyUpdate(bytes32 shell_id, bytes calldata new_recovery_pubkey) external;
    function confirmRecoveryKeyUpdate(bytes32 shell_id) external;

    function updateCapabilityHash(bytes32 shell_id, bytes32 new_capability_hash) external;
    function setPayoutAddress(bytes32 shell_id, address new_payout_address) external;

    // ─── Certificate and Tier Management ─────────────────────────────────────

    /// @notice Set or update the Shell's Attestation Certificate.
    /// @dev MUST verify K_v_threshold valid signatures from active VerifierRegistry verifiers.
    ///      MUST collect F_cert fee via ERC20.transferFrom.
    function setCertificate(bytes32 shell_id, bytes calldata cert_data, bytes[] calldata sigs_verifiers) external;
    function revokeCertificate(bytes32 shell_id) external;

    // ─── Bond Lifecycle ──────────────────────────────────────────────────────

    function beginUnbond(bytes32 shell_id, uint256 amount) external;
    function finalizeUnbond(bytes32 shell_id) external;

    function bondSafeHaven(bytes32 shell_id, uint256 amount) external;
    function beginUnbondSafeHaven(bytes32 shell_id) external;
    function finalizeUnbondSafeHaven(bytes32 shell_id) external;

    // ─── Slashing ────────────────────────────────────────────────────────────

    /// @notice Slash a Shell's bond (callable by ReceiptManager only).
    function slashShell(bytes32 shell_id, uint256 amount, bytes32 reason) external;

    /// @notice Slash a Safe Haven's bond (callable by SessionManager only).
    function slashSafeHaven(bytes32 shell_id, uint256 amount, address challenger) external;

    // ─── Views ───────────────────────────────────────────────────────────────

    function getShell(bytes32 shell_id) external view returns (ShellRecord memory);
    function assuranceTier(bytes32 shell_id) external view returns (uint8);
}
