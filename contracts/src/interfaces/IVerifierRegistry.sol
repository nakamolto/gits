// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVerifierRegistry — Verifier Staking, Measurement Allowlist, and Equivocation Proofs
/// @notice Maintains the active verifier set for Attestation Certificates and RBCs (Section 14.7).
interface IVerifierRegistry {
    // ─── Events ──────────────────────────────────────────────────────────────

    event VerifierRegistered(address indexed verifier, address asset, uint256 amount);
    event StakeIncreased(address indexed verifier, address asset, uint256 amount);
    event StakeDecreaseBegun(address indexed verifier, address asset, uint256 amount, uint256 available_epoch);
    event StakeWithdrawn(address indexed verifier, address asset, uint256 amount);
    event VerifierSlashed(address indexed verifier, address asset, uint256 amount, bytes32 reason);
    event MeasurementAllowed(bytes32 indexed measurement_hash, uint8 tier_class);
    event MeasurementRevoked(bytes32 indexed measurement_hash);

    // ─── Verifier Staking ────────────────────────────────────────────────────

    function registerVerifier(address asset, uint256 amount) external;
    function increaseStake(address asset, uint256 amount) external;
    function beginDecreaseStake(address asset, uint256 amount) external;
    function withdrawDecreasedStake(address asset) external;

    /// @notice Slash a verifier's stake. Callable by authorized protocol contracts only.
    function slashVerifier(address verifier, address asset, uint256 amount, bytes32 reason) external;

    /// @notice Permissionless equivocation proof: two conflicting certificate signatures.
    /// @dev On success: slashes full stake. Challenger receives bps_verifier_challenger_reward.
    function proveVerifierEquivocation(
        address verifier,
        bytes32 shell_id,
        bytes calldata ac_payload_a,
        bytes calldata sig_a,
        bytes calldata ac_payload_b,
        bytes calldata sig_b
    ) external;

    // ─── Measurement Allowlist ───────────────────────────────────────────────

    /// @notice Allow a measurement hash. Loosening action: requires K_v_supermajority quorum.
    /// @param tier_class 0 = Confidential Shell, 1 = Safe Haven (stricter).
    function allowMeasurement(bytes32 measurement_hash, uint8 tier_class, uint64 nonce, bytes[] calldata sigs_verifiers) external;

    /// @notice Revoke a measurement hash. Tightening action: standard K_v_threshold quorum.
    function revokeMeasurement(bytes32 measurement_hash, uint64 nonce, bytes[] calldata sigs_verifiers) external;

    // ─── Views ───────────────────────────────────────────────────────────────

    function isActiveVerifier(address verifier) external view returns (bool);
    function stakeScore(address verifier) external view returns (uint256);
    function activeStake(address verifier, address asset) external view returns (uint256);
    function isMeasurementAllowed(bytes32 measurement_hash, uint8 tier_class) external view returns (bool);
}
