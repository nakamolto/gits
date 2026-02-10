// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGhostRegistry} from "./interfaces/IGhostRegistry.sol";
import {GhostRecord, RecoveryConfig} from "./types/GITSTypes.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title GhostRegistry — Ghost Identity and Recovery Configuration
/// @notice Anchors Ghost identity, checkpoint pointers, recovery config, and optional bond/reward history gates.
/// @dev Spec: Part 3, Section 14.2.
contract GhostRegistry is IGhostRegistry {
    using SafeERC20 for IERC20;

    // ─── Constants / Tags ────────────────────────────────────────────────────

    bytes32 internal constant GHOST_ID_TAG_HASH = keccak256(bytes("GITS_GHOST_ID"));
    bytes32 internal constant ROTATE_TAG_HASH = keccak256(bytes("GITS_GHOST_ROTATE"));

    // ─── Deployment Params ───────────────────────────────────────────────────

    address public immutable SESSION_MANAGER;
    address public immutable REWARDS_MANAGER;

    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    uint256 public immutable T_GHOST_AGE;
    uint256 public immutable B_GHOST_REWARD_MIN;
    uint256 public immutable T_UNBOND_GHOST;

    mapping(address => bool) public bondAssetAllowed;

    // ─── Storage ────────────────────────────────────────────────────────────

    mapping(bytes32 => GhostRecord) private ghosts; // ghost_id => record

    // Tracks the currently scheduled withdrawal amount (single-active-unbond rule).
    mapping(bytes32 => uint256) private unbondAmount;

    // Reward history credit used for passport eligibility (see ghostPassportEligible).
    mapping(bytes32 => uint256) public cumulativeRewards;

    // ─── Errors ─────────────────────────────────────────────────────────────

    error GhostNotRegistered(bytes32 ghost_id);
    error GhostAlreadyRegistered(bytes32 ghost_id);
    error GhostIdMismatch(bytes32 supplied, bytes32 expected);
    error Unauthorized();
    error InvalidEpochClock();
    error InvalidAmount();
    error AssetNotAllowed(address asset);
    error UnsupportedSigAlg(uint8 alg);
    error InvalidProof();
    error UnbondPending(uint256 unbond_end_epoch);
    error UnbondNotReady(uint256 unbond_end_epoch);
    error InvalidRecoveryConfig();

    // ─── Events ─────────────────────────────────────────────────────────────

    event GhostRegistered(bytes32 indexed ghost_id, address indexed wallet);
    event SignerRotated(bytes32 indexed ghost_id, bytes new_identity_pubkey);
    event CheckpointPublished(
        bytes32 indexed ghost_id,
        uint256 epoch,
        bytes32 checkpointCommitment,
        bytes32 envelopeCommitment
    );
    event RecoveryConfigSet(bytes32 indexed ghost_id, uint64 threshold);

    event GhostBonded(bytes32 indexed ghost_id, address indexed asset, uint256 amount);
    event GhostUnbondStarted(bytes32 indexed ghost_id, uint256 amount, uint256 unbond_end_epoch);
    event GhostUnbondFinalized(bytes32 indexed ghost_id, uint256 amount);

    event RewardCredited(bytes32 indexed ghost_id, uint256 amount, uint256 newTotal);

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address sessionManager_,
        address rewardsManager_,
        uint256 genesisTime_,
        uint256 epochLen_,
        uint256 tGhostAge_,
        uint256 bGhostRewardMin_,
        uint256 tUnbondGhost_,
        address[] memory bondAssets_
    ) {
        SESSION_MANAGER = sessionManager_;
        REWARDS_MANAGER = rewardsManager_;

        GENESIS_TIME = genesisTime_;
        EPOCH_LEN = epochLen_;

        T_GHOST_AGE = tGhostAge_;
        B_GHOST_REWARD_MIN = bGhostRewardMin_;
        T_UNBOND_GHOST = tUnbondGhost_;

        for (uint256 i = 0; i < bondAssets_.length; i++) {
            bondAssetAllowed[bondAssets_[i]] = true;
        }
    }

    // ─── Registration ────────────────────────────────────────────────────────

    function registerGhost(
        bytes32 ghost_id,
        bytes calldata identity_pubkey,
        address wallet,
        bytes32 salt,
        RecoveryConfig calldata recoveryConfig
    ) external {
        if (msg.sender != wallet) revert Unauthorized();
        if (wallet == address(0)) revert Unauthorized();

        _requireSupportedIdentityKey(identity_pubkey);
        _validateRecoveryConfig(recoveryConfig);

        bytes32 expected_id = keccak256(abi.encode(GHOST_ID_TAG_HASH, identity_pubkey, wallet, salt));
        if (ghost_id != expected_id) revert GhostIdMismatch(ghost_id, expected_id);

        if (ghosts[expected_id].wallet != address(0)) revert GhostAlreadyRegistered(expected_id);

        GhostRecord storage g = ghosts[expected_id];
        g.ghost_id = expected_id;
        g.identity_pubkey = identity_pubkey;
        g.wallet = wallet;
        g.recovery_config = recoveryConfig;
        g.registered_epoch = _currentEpoch();

        emit GhostRegistered(expected_id, wallet);
    }

    // ─── Reward History Credit (Eligibility Gate) ───────────────────────────

    /// @notice Credit cumulative reward history for a Ghost.
    /// @dev Callable ONLY by RewardsManager. Used by ghostPassportEligible.
    function recordRewardCredit(bytes32 ghost_id, uint256 amount) external {
        if (msg.sender != REWARDS_MANAGER) revert Unauthorized();
        _ghostOrRevert(ghost_id);
        if (amount == 0) revert InvalidAmount();

        uint256 newTotal = cumulativeRewards[ghost_id] + amount;
        cumulativeRewards[ghost_id] = newTotal;

        emit RewardCredited(ghost_id, amount, newTotal);
    }

    // ─── Bond Lifecycle (passport eligibility) ───────────────────────────────

    function bondGhost(bytes32 ghost_id, address asset, uint256 amount) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);
        if (msg.sender != g.wallet) revert Unauthorized();
        if (!bondAssetAllowed[asset]) revert AssetNotAllowed(asset);
        if (amount == 0) revert InvalidAmount();

        if (g.bond_amount == 0) {
            g.bond_asset = asset;
        } else if (g.bond_asset != asset) {
            revert AssetNotAllowed(asset);
        }

        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        g.bond_amount += amount;

        emit GhostBonded(ghost_id, asset, amount);
    }

    function beginUnbondGhost(bytes32 ghost_id, uint256 amount) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);
        if (msg.sender != g.wallet) revert Unauthorized();
        if (amount == 0 || amount > g.bond_amount) revert InvalidAmount();

        // Single active unbond: MUST revert if already unbonding.
        if (g.unbond_end_epoch != 0) revert UnbondPending(g.unbond_end_epoch);

        uint256 endEpoch = _currentEpoch() + T_UNBOND_GHOST;
        g.unbond_end_epoch = endEpoch;
        unbondAmount[ghost_id] = amount;

        emit GhostUnbondStarted(ghost_id, amount, endEpoch);
    }

    function finalizeUnbondGhost(bytes32 ghost_id) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);
        if (msg.sender != g.wallet) revert Unauthorized();

        uint256 endEpoch = g.unbond_end_epoch;
        if (endEpoch == 0) revert InvalidAmount();

        if (_currentEpoch() < endEpoch) revert UnbondNotReady(endEpoch);

        uint256 amount = unbondAmount[ghost_id];
        address asset = g.bond_asset;

        // Clear unbonding state first (defensive reentrancy posture; ERC20s should be well-behaved).
        g.unbond_end_epoch = 0;
        unbondAmount[ghost_id] = 0;

        g.bond_amount -= amount;
        if (g.bond_amount == 0) {
            g.bond_asset = address(0);
        }

        IERC20(asset).safeTransfer(g.wallet, amount);

        emit GhostUnbondFinalized(ghost_id, amount);
    }

    function ghostPassportEligible(bytes32 ghost_id, uint256 epoch) external view returns (bool) {
        GhostRecord storage g = ghosts[ghost_id];
        if (g.wallet == address(0)) return false;

        // Age gate
        if (epoch < T_GHOST_AGE) return false;
        if (g.registered_epoch > epoch - T_GHOST_AGE) return false;

        // Reward history gate
        if (cumulativeRewards[ghost_id] < B_GHOST_REWARD_MIN) return false;

        // Bond gate
        if (g.bond_amount < B_GHOST_REWARD_MIN) return false;
        if (g.bond_asset == address(0) || !bondAssetAllowed[g.bond_asset]) return false;

        // Unbonding gate (strict): ineligible while currently unbonding.
        if (g.unbond_end_epoch != 0 && epoch < g.unbond_end_epoch) return false;

        return true;
    }

    // ─── Identity Key Rotation ───────────────────────────────────────────────

    function rotateSigner(bytes32 ghost_id, bytes calldata new_identity_pubkey, bytes calldata proof) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);

        _requireSupportedIdentityKey(new_identity_pubkey);

        if (msg.sender == g.wallet) {
            // Normal path: proof must be a signature by the CURRENT identity key over the rotation digest.
            bytes32 digest = keccak256(abi.encode(ROTATE_TAG_HASH, ghost_id, new_identity_pubkey, block.chainid));
            address expectedSigner = _k1AddressFromIdentityKey(g.identity_pubkey);

            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, proof);
            if (err != ECDSA.RecoverError.NoError || recovered != expectedSigner) revert InvalidProof();
        } else if (msg.sender == SESSION_MANAGER) {
            // Recovery path: authorization comes from SessionManager.recoveryRotate; proof MUST be empty.
            if (proof.length != 0) revert InvalidProof();
        } else {
            revert Unauthorized();
        }

        g.identity_pubkey = new_identity_pubkey;
        emit SignerRotated(ghost_id, new_identity_pubkey);
    }

    // ─── Checkpoint Management ───────────────────────────────────────────────

    function publishCheckpoint(
        bytes32 ghost_id,
        uint256 epoch,
        bytes32 checkpointCommitment,
        bytes32 envelopeCommitment,
        bytes calldata ptrCheckpoint,
        bytes calldata ptrEnvelope
    ) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);
        if (msg.sender != g.wallet) revert Unauthorized();

        // Defensive: prevent stale checkpoint overwrite.
        if (epoch < g.checkpoint_epoch) revert InvalidEpochClock();

        g.checkpoint_commitment = checkpointCommitment;
        g.envelope_commitment = envelopeCommitment;
        g.ptr_checkpoint = ptrCheckpoint;
        g.ptr_envelope = ptrEnvelope;
        g.checkpoint_epoch = epoch;

        emit CheckpointPublished(ghost_id, epoch, checkpointCommitment, envelopeCommitment);
    }

    // ─── Recovery Config ─────────────────────────────────────────────────────

    function setRecoveryConfig(bytes32 ghost_id, RecoveryConfig calldata recoveryConfig) external {
        GhostRecord storage g = _ghostOrRevert(ghost_id);
        if (msg.sender != g.wallet) revert Unauthorized();

        _validateRecoveryConfig(recoveryConfig);
        g.recovery_config = recoveryConfig;

        emit RecoveryConfigSet(ghost_id, recoveryConfig.threshold);
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    function getGhost(bytes32 ghost_id) external view returns (GhostRecord memory) {
        GhostRecord storage g = ghosts[ghost_id];
        if (g.wallet == address(0)) revert GhostNotRegistered(ghost_id);
        return g;
    }

    // ─── Internal Helpers ────────────────────────────────────────────────────

    function _ghostOrRevert(bytes32 ghost_id) internal view returns (GhostRecord storage) {
        GhostRecord storage g = ghosts[ghost_id];
        if (g.wallet == address(0)) revert GhostNotRegistered(ghost_id);
        return g;
    }

    function _currentEpoch() internal view returns (uint256) {
        if (EPOCH_LEN == 0) revert InvalidEpochClock();
        if (block.timestamp < GENESIS_TIME) revert InvalidEpochClock();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    function _validateRecoveryConfig(RecoveryConfig calldata cfg) internal pure {
        uint256 n = cfg.recovery_set.length;
        if (n == 0) revert InvalidRecoveryConfig();
        if (cfg.threshold == 0 || uint256(cfg.threshold) > n) revert InvalidRecoveryConfig();
        if (cfg.bps_initiator > 10_000) revert InvalidRecoveryConfig();
    }

    function _requireSupportedIdentityKey(bytes calldata identity_pubkey) internal pure {
        (uint8 alg,) = abi.decode(identity_pubkey, (uint8, bytes));
        if (alg != 1) revert UnsupportedSigAlg(alg);
    }

    function _k1AddressFromIdentityKey(bytes memory identity_pubkey) internal pure returns (address) {
        (uint8 alg, bytes memory pkBytes) = abi.decode(identity_pubkey, (uint8, bytes));
        if (alg != 1) revert UnsupportedSigAlg(alg);
        return abi.decode(pkBytes, (address));
    }
}
