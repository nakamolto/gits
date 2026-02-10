// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IRewardsManager} from "./interfaces/IRewardsManager.sol";
import {IGIT} from "./interfaces/IGIT.sol";
import {IReceiptManager} from "./interfaces/IReceiptManager.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IShellRegistry} from "./interfaces/IShellRegistry.sol";
import {IGhostRegistry} from "./interfaces/IGhostRegistry.sol";

/// @dev Extended GhostRegistry interface for reward-history crediting. Kept local to avoid
///      interface file merge conflicts with other worktrees.
interface IGhostRegistryRewards is IGhostRegistry {
    function recordRewardCredit(bytes32 ghost_id, uint256 amount) external;
}

/// @title RewardsManager — Epoch Emissions and Reward Distribution
/// @notice Implements Section 14.6: aggregates receipt weights/SU per epoch, finalizes emissions,
///         and distributes pro-rata rewards to Ghost + Shell recipients.
contract RewardsManager is IRewardsManager {
    // ─────────────────────────────────────────────────────────────────────────────
    // Constants / Types
    // ─────────────────────────────────────────────────────────────────────────────

    uint256 internal constant Q64 = uint256(1) << 64; // Q64.64 scaling factor
    uint256 internal constant BPS_DENOM = 10_000;

    struct RewardsRefs {
        IGIT git;
        IReceiptManager receiptManager;
        ISessionManager sessionManager;
        IShellRegistry shellRegistry;
        address ghostRegistry; // cast to IGhostRegistryRewards when needed
    }

    struct RewardsConfig {
        // Emissions
        uint256 E_0;
        uint256 E_TAIL;
        uint256 HALVING_INTERVAL; // in epochs
        // Epoch clock
        uint256 GENESIS_TIME;
        uint256 EPOCH_LEN; // seconds
        // Finalization
        uint256 EPOCH_FINALIZATION_DELAY;
        uint256 FINALIZATION_GRACE;
        // Claims
        uint256 W_CLAIM; // in epochs
        // Uptime
        uint256 W_UPTIME; // window size (epochs)
        uint32 SU_UPTIME_EPOCH_MIN;
        uint16 E_uptime_min; // min live epochs in lookback
        // Utilization and caps
        uint256 SU_TARGET; // capacity denominator
        uint32 SU_CAP_PER_SHELL;
        // Splits (bps)
        uint16 ALPHA_BPS; // Ghost share
        uint16 BETA_BPS;  // Shell share
        // Eligibility
        uint256 B_reward_min;
        uint256 T_age;
        uint256 B_ghost_reward_min;
        uint256 T_ghost_age;
        uint256 MIN_WEIGHT_Q;
        // Adaptive sink
        uint256 u_sink_start_q; // Q64.64
        uint256 u_sink_full_q;  // Q64.64
        uint16 bps_sink_max;
    }

    struct ReceiptData {
        bool exists;
        bool claimed;
        bool rewardEligible;
        uint256 epoch;
        bytes32 ghost_id;
        bytes32 shell_id;
        uint32 su_delivered;
        uint256 weight_q; // effective weight (0 if ineligible/late)
    }

    struct EpochData {
        bool finalized;
        uint256 totalWeight_q;
        uint256 suEligible;
        uint256 receiptCount;
        // Finalized per-epoch reward rates (Q64.64) and observability
        uint256 rateGhost_q;
        uint256 rateShell_q;
        uint256 eSched;
        uint256 eGhostNet;
        uint256 eShellNet;
        uint256 bpsSink;
        uint256 uTotal_q;
        uint256 mintedNet;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Errors / Events
    // ─────────────────────────────────────────────────────────────────────────────

    error GenesisNotReached();
    error OnlyReceiptManager();
    error DuplicateReceipt(bytes32 receipt_id);
    error WeightTooLow(uint256 weight_q);
    error EpochAlreadyFinalized(uint256 epoch);
    error PendingDA(uint256 epoch);
    error FinalizeTooEarly(uint256 epoch, uint256 current_epoch);
    error EpochNotFinalized(uint256 epoch);
    error UnknownReceipt(bytes32 receipt_id);
    error ReceiptAlreadyClaimed(bytes32 receipt_id);
    error ClaimExpired(bytes32 receipt_id, uint256 current_epoch);
    error ClaimsNotExpired(uint256 epoch, uint256 current_epoch);
    error BadConfig();
    error TransferFailed();
    error RegistryCallFailed();

    event ReceiptRecorded(
        bytes32 indexed receipt_id,
        uint256 indexed epoch,
        bytes32 indexed shell_id,
        bytes32 ghost_id,
        uint32 su_delivered,
        uint256 weight_q,
        bool rewardEligible
    );

    event EpochFinalized(
        uint256 indexed epoch,
        uint256 eSched,
        uint256 suEligible,
        uint256 totalWeight_q,
        uint256 eGhostNet,
        uint256 eShellNet,
        uint256 rateGhost_q,
        uint256 rateShell_q,
        uint256 bpsSink,
        uint256 mintedNet
    );

    event ReceiptClaimed(
        bytes32 indexed receipt_id,
        bytes32 indexed ghost_id,
        bytes32 indexed shell_id,
        uint256 ghostAmount,
        uint256 shellAmount
    );

    event EpochPruned(uint256 indexed epoch);
    event ReceiptPruned(bytes32 indexed receipt_id);

    // ─────────────────────────────────────────────────────────────────────────────
    // Immutable Refs + Config
    // ─────────────────────────────────────────────────────────────────────────────

    IGIT public immutable git;
    IReceiptManager public immutable receiptManager;
    ISessionManager public immutable sessionManager;
    IShellRegistry public immutable shellRegistry;
    address public immutable ghostRegistry;

    uint256 public immutable E_0;
    uint256 public immutable E_TAIL;
    uint256 public immutable HALVING_INTERVAL;
    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;
    uint256 public immutable EPOCH_FINALIZATION_DELAY;
    uint256 public immutable FINALIZATION_GRACE;
    uint256 public immutable W_CLAIM;
    uint256 public immutable W_UPTIME;
    uint32 public immutable SU_UPTIME_EPOCH_MIN;
    uint16 public immutable E_uptime_min;
    uint256 public immutable SU_TARGET;
    uint32 public immutable SU_CAP_PER_SHELL;
    uint16 public immutable ALPHA_BPS;
    uint16 public immutable BETA_BPS;
    uint256 public immutable B_reward_min;
    uint256 public immutable T_age;
    uint256 public immutable B_ghost_reward_min;
    uint256 public immutable T_ghost_age;
    uint256 public immutable MIN_WEIGHT_Q;
    uint256 public immutable u_sink_start_q;
    uint256 public immutable u_sink_full_q;
    uint16 public immutable bps_sink_max;

    // ─────────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────────

    mapping(bytes32 => ReceiptData) public receipts;
    mapping(uint256 => EpochData) public epochs;

    // Per-shell, per-epoch SU (for cap + uptime)
    mapping(bytes32 => mapping(uint256 => uint32)) public eligibleSU_shell;
    mapping(bytes32 => mapping(uint256 => uint256)) public epochSU;

    // Uptime ring buffer per shell (window size W_UPTIME)
    mapping(bytes32 => uint256) private lastRingEpochPlusOne; // 0 => none committed
    mapping(bytes32 => uint256) private ringLiveCount;
    mapping(bytes32 => mapping(uint256 => bool)) private ringLiveAtSlot; // slot => live?

    // ─────────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────────

    constructor(RewardsRefs memory refs, RewardsConfig memory cfg) {
        if (
            address(refs.git) == address(0) || address(refs.receiptManager) == address(0)
                || address(refs.shellRegistry) == address(0) || refs.ghostRegistry == address(0)
        ) revert BadConfig();
        if (cfg.EPOCH_LEN == 0 || cfg.SU_TARGET == 0 || cfg.HALVING_INTERVAL == 0 || cfg.W_UPTIME == 0) revert BadConfig();
        if (uint256(cfg.ALPHA_BPS) + uint256(cfg.BETA_BPS) != BPS_DENOM) revert BadConfig();
        if (cfg.u_sink_full_q < cfg.u_sink_start_q) revert BadConfig();
        if (cfg.E_0 + cfg.E_TAIL == 0) revert BadConfig();

        git = refs.git;
        receiptManager = refs.receiptManager;
        sessionManager = refs.sessionManager;
        shellRegistry = refs.shellRegistry;
        ghostRegistry = refs.ghostRegistry;

        E_0 = cfg.E_0;
        E_TAIL = cfg.E_TAIL;
        HALVING_INTERVAL = cfg.HALVING_INTERVAL;
        GENESIS_TIME = cfg.GENESIS_TIME;
        EPOCH_LEN = cfg.EPOCH_LEN;
        EPOCH_FINALIZATION_DELAY = cfg.EPOCH_FINALIZATION_DELAY;
        FINALIZATION_GRACE = cfg.FINALIZATION_GRACE;
        W_CLAIM = cfg.W_CLAIM;
        W_UPTIME = cfg.W_UPTIME;
        SU_UPTIME_EPOCH_MIN = cfg.SU_UPTIME_EPOCH_MIN;
        E_uptime_min = cfg.E_uptime_min;
        SU_TARGET = cfg.SU_TARGET;
        SU_CAP_PER_SHELL = cfg.SU_CAP_PER_SHELL;
        ALPHA_BPS = cfg.ALPHA_BPS;
        BETA_BPS = cfg.BETA_BPS;
        B_reward_min = cfg.B_reward_min;
        T_age = cfg.T_age;
        B_ghost_reward_min = cfg.B_ghost_reward_min;
        T_ghost_age = cfg.T_ghost_age;
        MIN_WEIGHT_Q = cfg.MIN_WEIGHT_Q;
        u_sink_start_q = cfg.u_sink_start_q;
        u_sink_full_q = cfg.u_sink_full_q;
        bps_sink_max = cfg.bps_sink_max;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // External API
    // ─────────────────────────────────────────────────────────────────────────────

    /// @inheritdoc IRewardsManager
    function recordReceipt(
        bytes32 receipt_id,
        uint256 epoch,
        bytes32 ghost_id,
        bytes32 shell_id,
        uint32 su_delivered,
        uint256 weight_q
    ) external override {
        if (block.timestamp < GENESIS_TIME) revert GenesisNotReached();
        if (msg.sender != address(receiptManager)) revert OnlyReceiptManager();

        ReceiptData storage r = receipts[receipt_id];
        if (r.exists) revert DuplicateReceipt(receipt_id);

        r.exists = true;
        r.epoch = epoch;
        r.ghost_id = ghost_id;
        r.shell_id = shell_id;
        r.su_delivered = su_delivered;

        EpochData storage e = epochs[epoch];
        if (e.finalized) {
            // Late receipt: store it, but do not alter finalized epoch accounting.
            emit ReceiptRecorded(receipt_id, epoch, shell_id, ghost_id, su_delivered, 0, false);
            return;
        }

        if (su_delivered > 0 && weight_q < MIN_WEIGHT_Q) revert WeightTooLow(weight_q);

        // Advance ring to cover the uptime lookback for this service epoch.
        _advanceRingTo(shell_id, epoch);

        bool shellEligible = _isShellRewardEligible(shell_id, epoch);
        bool ghostEligible = _isGhostRewardEligible(ghost_id, epoch);
        bool eligible = shellEligible && ghostEligible;

        if (eligible) {
            uint32 prev = eligibleSU_shell[shell_id][epoch];
            uint256 next = uint256(prev) + uint256(su_delivered);
            if (next > uint256(SU_CAP_PER_SHELL)) {
                eligible = false;
            } else {
                eligibleSU_shell[shell_id][epoch] = uint32(next);
            }
        }

        if (eligible) {
            r.rewardEligible = true;
            r.weight_q = weight_q;
            e.totalWeight_q += weight_q;
            e.suEligible += su_delivered;
        } else {
            r.rewardEligible = false;
            r.weight_q = 0;
        }

        // Always accumulate shell SU for uptime liveness calculation.
        epochSU[shell_id][epoch] += su_delivered;

        e.receiptCount += 1;

        emit ReceiptRecorded(receipt_id, epoch, shell_id, ghost_id, su_delivered, r.weight_q, r.rewardEligible);
    }

    /// @inheritdoc IRewardsManager
    function finalizeEpoch(uint256 epoch) external override {
        uint256 current = _currentEpoch();

        EpochData storage e = epochs[epoch];
        if (e.finalized) revert EpochAlreadyFinalized(epoch);

        if (receiptManager.pendingDACount(epoch) > 0) revert PendingDA(epoch);

        uint256 minEpoch = epoch + 1 + EPOCH_FINALIZATION_DELAY + FINALIZATION_GRACE;
        if (current < minEpoch) revert FinalizeTooEarly(epoch, current);

        uint256 totalWeight = e.totalWeight_q;
        uint256 suEligible = e.suEligible;

        uint256 eSched = _computeESched(epoch);
        uint256 uTotal_q = Math.min(Q64, Math.mulDiv(suEligible, Q64, SU_TARGET));

        uint256 gross = (suEligible >= SU_TARGET) ? eSched : Math.mulDiv(eSched, suEligible, SU_TARGET);

        uint256 bpsSink = _computeBpsSink(eSched, uTotal_q, gross);

        uint256 netTotal = gross;
        if (bpsSink != 0) netTotal = gross - Math.mulDiv(gross, bpsSink, BPS_DENOM);

        uint256 ghostNet = Math.mulDiv(netTotal, ALPHA_BPS, BPS_DENOM);
        uint256 shellNet = netTotal - ghostNet; // alpha+beta == 1.0 => remainder goes to Shell

        uint256 rateGhost_q = 0;
        uint256 rateShell_q = 0;
        if (totalWeight != 0) {
            rateGhost_q = Math.mulDiv(ghostNet, Q64, totalWeight);
            rateShell_q = Math.mulDiv(shellNet, Q64, totalWeight);
        } else {
            // No eligible weight => mint nothing.
            ghostNet = 0;
            shellNet = 0;
            netTotal = 0;
        }

        uint256 mintedNet = netTotal;
        if (mintedNet != 0) git.mint(address(this), mintedNet);

        e.finalized = true;
        e.rateGhost_q = rateGhost_q;
        e.rateShell_q = rateShell_q;
        e.eSched = eSched;
        e.eGhostNet = ghostNet;
        e.eShellNet = shellNet;
        e.bpsSink = bpsSink;
        e.uTotal_q = uTotal_q;
        e.mintedNet = mintedNet;

        emit EpochFinalized(
            epoch,
            eSched,
            suEligible,
            totalWeight,
            ghostNet,
            shellNet,
            rateGhost_q,
            rateShell_q,
            bpsSink,
            mintedNet
        );
    }

    /// @inheritdoc IRewardsManager
    function claimReceiptRewards(bytes32 receipt_id) external override {
        uint256 current = _currentEpoch();

        ReceiptData storage r = receipts[receipt_id];
        if (!r.exists) revert UnknownReceipt(receipt_id);
        if (r.claimed) revert ReceiptAlreadyClaimed(receipt_id);

        EpochData storage e = epochs[r.epoch];
        if (!e.finalized) revert EpochNotFinalized(r.epoch);

        if (current > r.epoch + W_CLAIM) revert ClaimExpired(receipt_id, current);

        // Effects first (reentrancy-safe).
        r.claimed = true;

        uint256 ghostAmt;
        uint256 shellAmt;

        if (r.rewardEligible) {
            ghostAmt = Math.mulDiv(e.rateGhost_q, r.weight_q, Q64);
            shellAmt = Math.mulDiv(e.rateShell_q, r.weight_q, Q64);
        }

        if (ghostAmt != 0) {
            address gw = _getGhostWallet(r.ghost_id);
            SafeERC20.safeTransfer(IERC20(address(git)), gw, ghostAmt);
            IGhostRegistryRewards(ghostRegistry).recordRewardCredit(r.ghost_id, ghostAmt);
        }

        if (shellAmt != 0) {
            address payout = _getShellPayout(r.shell_id);
            SafeERC20.safeTransfer(IERC20(address(git)), payout, shellAmt);
        }

        emit ReceiptClaimed(receipt_id, r.ghost_id, r.shell_id, ghostAmt, shellAmt);
    }

    /// @inheritdoc IRewardsManager
    function pruneEpoch(uint256 epoch) external override {
        uint256 current = _currentEpoch();
        if (current <= epoch + W_CLAIM) revert ClaimsNotExpired(epoch, current);

        EpochData storage e = epochs[epoch];
        if (!e.finalized) revert EpochNotFinalized(epoch);

        delete epochs[epoch];
        emit EpochPruned(epoch);
    }

    /// @inheritdoc IRewardsManager
    function pruneReceipt(bytes32 receipt_id) external override {
        uint256 current = _currentEpoch();

        ReceiptData storage r = receipts[receipt_id];
        if (!r.exists) revert UnknownReceipt(receipt_id);

        if (!r.claimed) {
            if (current <= r.epoch + W_CLAIM) revert ClaimsNotExpired(r.epoch, current);
        }

        delete receipts[receipt_id];
        emit ReceiptPruned(receipt_id);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internals: Epoch clock
    // ─────────────────────────────────────────────────────────────────────────────

    function _currentEpoch() internal view returns (uint256) {
        if (block.timestamp < GENESIS_TIME) revert GenesisNotReached();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    function _computeESched(uint256 epoch) internal view returns (uint256) {
        // E_sched(epoch) = (E_0 * decay_q) / 2^64 + E_TAIL
        uint256 exponent_q = Math.mulDiv(epoch, Q64, HALVING_INTERVAL);
        uint256 decay_q = _negExp2Q64(exponent_q);
        return Math.mulDiv(E_0, decay_q, Q64) + E_TAIL;
    }

    function _computeBpsSink(uint256 eSched, uint256 uTotal_q, uint256 gross) internal view returns (uint256) {
        if (bps_sink_max == 0 || gross == 0) return 0;

        // s_q increases as schedule decays toward tail.
        uint256 eNorm_q = Math.min(Q64, Math.mulDiv(eSched, Q64, (E_0 + E_TAIL)));
        uint256 s_q = Q64 - eNorm_q;

        // r_q ramps in with utilization.
        uint256 r_q;
        if (uTotal_q <= u_sink_start_q) {
            r_q = 0;
        } else if (uTotal_q >= u_sink_full_q) {
            r_q = Q64;
        } else {
            r_q = Math.mulDiv(uTotal_q - u_sink_start_q, Q64, (u_sink_full_q - u_sink_start_q));
        }

        return Math.mulDiv(Math.mulDiv(uint256(bps_sink_max), s_q, Q64), r_q, Q64);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internals: Eligibility
    // ─────────────────────────────────────────────────────────────────────────────

    function _isShellRewardEligible(bytes32 shell_id, uint256 epoch) internal view returns (bool) {
        (address payout, uint256 bondAmount, uint8 bondStatus, uint256 registeredEpoch) = _getShellInfo(shell_id);
        if (payout == address(0)) return false;
        if (bondAmount < B_reward_min) return false;
        if (bondStatus != 0) return false; // not BONDED
        if (epoch < T_age) return false;
        if (registeredEpoch > epoch - T_age) return false;

        // Uptime lookback: [epoch - W_UPTIME - 1, epoch - 2] inclusive, window length W_UPTIME.
        // We advance ring to epoch-2 in recordReceipt, so ringLiveCount holds the trailing window.
        if (ringLiveCount[shell_id] < uint256(E_uptime_min)) return false;

        return true;
    }

    function _isGhostRewardEligible(bytes32 ghost_id, uint256 epoch) internal view returns (bool) {
        (address wallet, uint256 bondAmount, uint256 unbondEndEpoch, uint256 registeredEpoch) = _getGhostInfo(ghost_id);
        if (wallet == address(0)) return false;
        if (bondAmount < B_ghost_reward_min) return false;
        if (unbondEndEpoch != 0) return false; // treat any unbonding as ineligible at record time
        if (epoch < T_ghost_age) return false;
        if (registeredEpoch > epoch - T_ghost_age) return false;

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internals: Registry Field Extraction (avoid decoding full dynamic structs)
    // ─────────────────────────────────────────────────────────────────────────────

    function _getShellInfo(bytes32 shell_id)
        internal
        view
        returns (address payout, uint256 bondAmount, uint8 bondStatus, uint256 registeredEpoch)
    {
        (bool ok, bytes memory data) =
            address(shellRegistry).staticcall(abi.encodeWithSelector(IShellRegistry.getShell.selector, shell_id));
        if (!ok) revert RegistryCallFailed();
        // ShellRecord fields (ABI head):
        //  0 shell_id
        //  1 identity_pubkey offset
        //  2 offer_signer_pubkey offset
        //  3 payout_address
        //  4 bond_asset
        //  5 bond_amount
        //  6 bond_status
        // ...
        // 14 registered_epoch
        assembly {
            payout := mload(add(data, 128)) // 32 + 3*32 = 128 (address is right-aligned)
            bondAmount := mload(add(data, 192)) // 32 + 5*32 = 192
            bondStatus := and(mload(add(data, 224)), 0xff) // 32 + 6*32 = 224
            registeredEpoch := mload(add(data, 480)) // 32 + 14*32 = 480
        }
    }

    function _getShellPayout(bytes32 shell_id) internal view returns (address payout) {
        (payout, , , ) = _getShellInfo(shell_id);
    }

    function _getGhostInfo(bytes32 ghost_id)
        internal
        view
        returns (address wallet, uint256 bondAmount, uint256 unbondEndEpoch, uint256 registeredEpoch)
    {
        (bool ok, bytes memory data) =
            ghostRegistry.staticcall(abi.encodeWithSelector(IGhostRegistry.getGhost.selector, ghost_id));
        if (!ok) revert RegistryCallFailed();
        // GhostRecord ABI head slots:
        //  0 ghost_id
        //  1 identity_pubkey offset
        //  2 wallet
        //  3 recovery_config offset
        //  4 checkpoint_commitment
        //  5 envelope_commitment
        //  6 ptr_checkpoint offset
        //  7 ptr_envelope offset
        //  8 checkpoint_epoch
        //  9 registered_epoch
        // 10 bond_asset
        // 11 bond_amount
        // 12 unbond_end_epoch
        assembly {
            wallet := mload(add(data, 96)) // 32 + 2*32 = 96 (address is right-aligned)
            registeredEpoch := mload(add(data, 320)) // 32 + 9*32 = 320
            bondAmount := mload(add(data, 384)) // 32 + 11*32 = 384
            unbondEndEpoch := mload(add(data, 416)) // 32 + 12*32 = 416
        }
    }

    function _getGhostWallet(bytes32 ghost_id) internal view returns (address wallet) {
        (wallet, , , ) = _getGhostInfo(ghost_id);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internals: Uptime ring buffer
    // ─────────────────────────────────────────────────────────────────────────────

    function _advanceRingTo(bytes32 shell_id, uint256 epoch) internal {
        // Need lookback window ending at epoch-2. For epoch < 2 there is no lookback.
        if (epoch < 2) return;

        uint256 target = epoch - 2;
        uint256 lastPlus1 = lastRingEpochPlusOne[shell_id];
        if (lastPlus1 == target + 1) return;
        if (lastPlus1 > target + 1) return; // out-of-order; ignore

        uint256 start = lastPlus1; // next epoch to commit (0 if none yet)
        uint256 steps = target - start + 1;

        if (steps > W_UPTIME) {
            // If we skipped more than a full window, the trailing window is all zeros.
            uint256 count = ringLiveCount[shell_id];
            if (count != 0) ringLiveCount[shell_id] = 0;
            for (uint256 i = 0; i < W_UPTIME; i++) {
                if (ringLiveAtSlot[shell_id][i]) ringLiveAtSlot[shell_id][i] = false;
            }
            lastRingEpochPlusOne[shell_id] = target + 1;
            return;
        }

        uint256 liveCount = ringLiveCount[shell_id];
        for (uint256 e = start; e <= target; e++) {
            bool live = epochSU[shell_id][e] >= SU_UPTIME_EPOCH_MIN;
            uint256 slot = e % W_UPTIME;
            if (ringLiveAtSlot[shell_id][slot]) {
                ringLiveAtSlot[shell_id][slot] = false;
                unchecked {
                    liveCount -= 1;
                }
            }
            if (live) {
                ringLiveAtSlot[shell_id][slot] = true;
                unchecked {
                    liveCount += 1;
                }
            }
            // Gas refund: we no longer need this epoch's raw SU once committed.
            if (epochSU[shell_id][e] != 0) delete epochSU[shell_id][e];
        }

        ringLiveCount[shell_id] = liveCount;
        lastRingEpochPlusOne[shell_id] = target + 1;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internals: neg_exp_2_64x64
    // ─────────────────────────────────────────────────────────────────────────────

    /// @notice Compute floor(2^64 * 2^(-x)) where x is Q64.64.
    /// @dev Returns 0 if x >= 64 (in Q64.64), matching the spec guard.
    function _negExp2Q64(uint256 x_q) internal pure returns (uint256) {
        if (x_q == 0) return Q64;
        if (x_q >= 64 * Q64) return 0;

        uint256 intPart = x_q >> 64; // 0..63
        uint256 fracPart = x_q & (Q64 - 1);

        // Apply integer part: 2^(-intPart)
        uint256 result = Q64 >> intPart;

        // Apply fractional bits (MSB to LSB).
        // Each constant is floor(2^64 * 2^(-2^-k)) for k=1..64.
        if (fracPart & 0x8000000000000000 != 0) result = (result * 0xb504f333f9de6484) >> 64;
        if (fracPart & 0x4000000000000000 != 0) result = (result * 0xd744fccad69d6af4) >> 64;
        if (fracPart & 0x2000000000000000 != 0) result = (result * 0xeac0c6e7dd24392e) >> 64;
        if (fracPart & 0x1000000000000000 != 0) result = (result * 0xf5257d152486cc2c) >> 64;
        if (fracPart & 0x0800000000000000 != 0) result = (result * 0xfa83b2db722a033a) >> 64;
        if (fracPart & 0x0400000000000000 != 0) result = (result * 0xfd3e0c0cf486c174) >> 64;
        if (fracPart & 0x0200000000000000 != 0) result = (result * 0xfe9e115c7b8f884b) >> 64;
        if (fracPart & 0x0100000000000000 != 0) result = (result * 0xff4ecb59511ec8a5) >> 64;
        if (fracPart & 0x0080000000000000 != 0) result = (result * 0xffa756521c8daed1) >> 64;
        if (fracPart & 0x0040000000000000 != 0) result = (result * 0xffd3a751c0f7e10b) >> 64;
        if (fracPart & 0x0020000000000000 != 0) result = (result * 0xffe9d2b2f7db2755) >> 64;
        if (fracPart & 0x0010000000000000 != 0) result = (result * 0xfff4e91bff1b8c3d) >> 64;
        if (fracPart & 0x0008000000000000 != 0) result = (result * 0xfffa747ea0040664) >> 64;
        if (fracPart & 0x0004000000000000 != 0) result = (result * 0xfffd3a3b7814eb53) >> 64;
        if (fracPart & 0x0002000000000000 != 0) result = (result * 0xfffe9d1cc60ddab1) >> 64;
        if (fracPart & 0x0001000000000000 != 0) result = (result * 0xffff4e8e25879bfa) >> 64;
        if (fracPart & 0x0000800000000000 != 0) result = (result * 0xffffa7470363f451) >> 64;
        if (fracPart & 0x0000400000000000 != 0) result = (result * 0xffffd3a37dda0313) >> 64;
        if (fracPart & 0x0000200000000000 != 0) result = (result * 0xffffe9d1bdf703ae) >> 64;
        if (fracPart & 0x0000100000000000 != 0) result = (result * 0xfffff4e8debe025e) >> 64;
        if (fracPart & 0x0000080000000000 != 0) result = (result * 0xfffffa746f4fa150) >> 64;
        if (fracPart & 0x0000040000000000 != 0) result = (result * 0xfffffd3a37a3f8b0) >> 64;
        if (fracPart & 0x0000020000000000 != 0) result = (result * 0xfffffe9d1bd1065a) >> 64;
        if (fracPart & 0x0000010000000000 != 0) result = (result * 0xffffff4e8de845ad) >> 64;
        if (fracPart & 0x0000008000000000 != 0) result = (result * 0xffffffa746f41376) >> 64;
        if (fracPart & 0x0000004000000000 != 0) result = (result * 0xffffffd3a37a05e3) >> 64;
        if (fracPart & 0x0000002000000000 != 0) result = (result * 0xffffffe9d1bd01fb) >> 64;
        if (fracPart & 0x0000001000000000 != 0) result = (result * 0xfffffff4e8de80c0) >> 64;
        if (fracPart & 0x0000000800000000 != 0) result = (result * 0xfffffffa746f4050) >> 64;
        if (fracPart & 0x0000000400000000 != 0) result = (result * 0xfffffffd3a37a024) >> 64;
        if (fracPart & 0x0000000200000000 != 0) result = (result * 0xfffffffe9d1bd011) >> 64;
        if (fracPart & 0x0000000100000000 != 0) result = (result * 0xffffffff4e8de808) >> 64;
        if (fracPart & 0x0000000080000000 != 0) result = (result * 0xffffffffa746f404) >> 64;
        if (fracPart & 0x0000000040000000 != 0) result = (result * 0xffffffffd3a37a02) >> 64;
        if (fracPart & 0x0000000020000000 != 0) result = (result * 0xffffffffe9d1bd01) >> 64;
        if (fracPart & 0x0000000010000000 != 0) result = (result * 0xfffffffff4e8de80) >> 64;
        if (fracPart & 0x0000000008000000 != 0) result = (result * 0xfffffffffa746f40) >> 64;
        if (fracPart & 0x0000000004000000 != 0) result = (result * 0xfffffffffd3a37a0) >> 64;
        if (fracPart & 0x0000000002000000 != 0) result = (result * 0xfffffffffe9d1bd0) >> 64;
        if (fracPart & 0x0000000001000000 != 0) result = (result * 0xffffffffff4e8de8) >> 64;
        if (fracPart & 0x0000000000800000 != 0) result = (result * 0xffffffffffa746f4) >> 64;
        if (fracPart & 0x0000000000400000 != 0) result = (result * 0xffffffffffd3a37a) >> 64;
        if (fracPart & 0x0000000000200000 != 0) result = (result * 0xffffffffffe9d1bd) >> 64;
        if (fracPart & 0x0000000000100000 != 0) result = (result * 0xfffffffffff4e8de) >> 64;
        if (fracPart & 0x0000000000080000 != 0) result = (result * 0xfffffffffffa746f) >> 64;
        if (fracPart & 0x0000000000040000 != 0) result = (result * 0xfffffffffffd3a37) >> 64;
        if (fracPart & 0x0000000000020000 != 0) result = (result * 0xfffffffffffe9d1b) >> 64;
        if (fracPart & 0x0000000000010000 != 0) result = (result * 0xffffffffffff4e8d) >> 64;
        if (fracPart & 0x0000000000008000 != 0) result = (result * 0xffffffffffffa746) >> 64;
        if (fracPart & 0x0000000000004000 != 0) result = (result * 0xffffffffffffd3a3) >> 64;
        if (fracPart & 0x0000000000002000 != 0) result = (result * 0xffffffffffffe9d1) >> 64;
        if (fracPart & 0x0000000000001000 != 0) result = (result * 0xfffffffffffff4e8) >> 64;
        if (fracPart & 0x0000000000000800 != 0) result = (result * 0xfffffffffffffa74) >> 64;
        if (fracPart & 0x0000000000000400 != 0) result = (result * 0xfffffffffffffd3a) >> 64;
        if (fracPart & 0x0000000000000200 != 0) result = (result * 0xfffffffffffffe9d) >> 64;
        if (fracPart & 0x0000000000000100 != 0) result = (result * 0xffffffffffffff4e) >> 64;
        if (fracPart & 0x0000000000000080 != 0) result = (result * 0xffffffffffffffa7) >> 64;
        if (fracPart & 0x0000000000000040 != 0) result = (result * 0xffffffffffffffd3) >> 64;
        if (fracPart & 0x0000000000000020 != 0) result = (result * 0xffffffffffffffe9) >> 64;
        if (fracPart & 0x0000000000000010 != 0) result = (result * 0xfffffffffffffff4) >> 64;
        if (fracPart & 0x0000000000000008 != 0) result = (result * 0xfffffffffffffffa) >> 64;
        if (fracPart & 0x0000000000000004 != 0) result = (result * 0xfffffffffffffffd) >> 64;
        if (fracPart & 0x0000000000000002 != 0) result = (result * 0xfffffffffffffffe) >> 64;
        if (fracPart & 0x0000000000000001 != 0) result = (result * 0xffffffffffffffff) >> 64;

        return result;
    }
}
