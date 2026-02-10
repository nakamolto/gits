// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IGhostRegistry} from "./interfaces/IGhostRegistry.sol";
import {IShellRegistry} from "./interfaces/IShellRegistry.sol";
import {IGhostWallet} from "./interfaces/IGhostWallet.sol";
import {IReceiptManager} from "./interfaces/IReceiptManager.sol";
import {IVerifierRegistry} from "./interfaces/IVerifierRegistry.sol";

import {
    SessionParams,
    SessionState,
    SessionMode,
    StrandedReason,
    BondStatus,
    RecoveryAttempt,
    RecoveryStatus,
    GhostRecord,
    ShellRecord,
    RBC,
    AuthSig,
    ShareReceipt,
    Policy
} from "./types/GITSTypes.sol";

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

/// @title SessionManager
/// @notice Session lifecycle, leases, residency, trust-refresh, migration, and recovery (GITS Part 3, Section 14.4).
contract SessionManager is ISessionManager, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ─── Tags (domain separation) ────────────────────────────────────────────

    bytes32 internal constant TAG_BLOOM = keccak256(bytes("GITS_PASSPORT_BLOOM"));
    bytes32 internal constant TAG_RECOVER_AUTH = keccak256(bytes("GITS_RECOVER_AUTH"));
    bytes32 internal constant TAG_SHARE = keccak256(bytes("GITS_SHARE"));
    bytes32 internal constant TAG_SHARE_ACK = keccak256(bytes("GITS_SHARE_ACK"));
    bytes32 internal constant TAG_RBC = keccak256(bytes("GITS_RBC"));

    // ─── Deployment Constants / Config ──────────────────────────────────────

    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    uint256 public immutable LEASE_DEFAULT; // epochs
    uint256 public immutable T_TRUST_REFRESH; // epochs

    uint256 public immutable T_RECOVERY_TIMEOUT; // epochs
    uint256 public immutable T_RECOVERY_TAKEOVER; // epochs
    uint256 public immutable T_RECOVERY_COOLDOWN; // epochs

    uint256 public immutable B_START; // native token bond for startRecovery/takeoverRecovery

    uint8 public immutable B_PASSPORT_FILTERS; // ring size
    uint256 public immutable C_PASSPORT; // epochs window
    uint256 public immutable BLOOM_M_BITS;
    uint8 public immutable BLOOM_K_HASHES;

    uint256 public immutable T_MIGRATION_TIMEOUT; // epochs

    uint64 public immutable K_VERIFIER_THRESHOLD; // quorum for RBC verifier signatures

    IGhostRegistry public immutable GHOST_REGISTRY;
    IShellRegistry public immutable SHELL_REGISTRY;
    IReceiptManager public immutable RECEIPT_MANAGER;
    IVerifierRegistry public immutable VERIFIER_REGISTRY;

    // ─── Bloom Ring Derived Constants ───────────────────────────────────────

    uint256 internal immutable BLOOM_WORDS; // number of 256-bit words per filter
    uint256 internal immutable PASSPORT_ROT_PERIOD; // epochs per filter rotation

    // ─── Core Session State ────────────────────────────────────────────────

    uint256 private _nextSessionId = 1;

    mapping(uint256 => SessionState) private _sessions;
    mapping(uint256 => bool) private _sessionExists;
    mapping(uint256 => SessionParams) private _paramsBySession;

    mapping(bytes32 => uint256) private _activeSessionIdByGhost;
    mapping(bytes32 => uint256) private _lastSessionIdByGhost;

    /// @dev STRANDED discovery requires mutation (processExpiry), but view functions may "virtually" strand.
    mapping(bytes32 => uint256) private _strandedSinceEpochPlusOneByGhost;

    // Trust refresh timestamp is stored as epoch+1 to avoid epoch 0 sentinel ambiguity.
    mapping(bytes32 => uint256) private _lastTrustRefreshEpochPlusOneByGhost;

    // ─── Dwell Anti-Gaming ─────────────────────────────────────────────────

    /// @dev dwellLastEpochPlusOne[ghost][shell] = last_close_epoch + 1 (0 = never)
    mapping(bytes32 => mapping(bytes32 => uint256)) private _dwellLastEpochPlusOne;
    /// @dev residencyStartEpochPlusOne[ghost][shell] = residency_start_epoch + 1 (0 = unknown)
    mapping(bytes32 => mapping(bytes32 => uint256)) private _residencyStartEpochPlusOneByGhostByShell;

    // ─── Escrow ────────────────────────────────────────────────────────────

    mapping(uint256 => mapping(uint256 => uint256)) private _escrowBySessionByEpoch;
    mapping(uint256 => uint256[]) private _escrowEpochListBySession;
    mapping(uint256 => mapping(uint256 => bool)) private _escrowEpochListed;

    // ─── Passport Bloom Filters (Rotating Ring) ────────────────────────────

    mapping(bytes32 => bool) private _bloomInit;
    mapping(bytes32 => uint256) private _bloomRotNum; // rotation number, not epoch
    mapping(bytes32 => uint8) private _bloomHead; // current filter index
    mapping(bytes32 => mapping(uint8 => mapping(uint256 => uint256))) private _bloomWord; // ghost => filter => wordIndex => 256-bit word

    // ─── Migration ─────────────────────────────────────────────────────────

    mapping(bytes32 => bytes32) private _migBundleHashByGhost;
    mapping(uint256 => uint256) private _stagingParentSession; // staging_session_id => parent_session_id

    // ─── Recovery ──────────────────────────────────────────────────────────

    mapping(bytes32 => uint64) private _nextAttemptIdByGhost;
    mapping(bytes32 => uint64) private _activeAttemptIdByGhost; // 0 if none
    mapping(bytes32 => mapping(uint64 => RecoveryAttempt)) private _recoveryAttemptByGhostById;
    mapping(bytes32 => mapping(uint64 => uint256)) private _recoveryBondByGhostById;

    /// @dev recoveryRotatedEpochPlusOne[ghost][attempt] = rotated_epoch + 1 (0 = not rotated)
    mapping(bytes32 => mapping(uint64 => uint256)) private _recoveryRotatedEpochPlusOneByGhostById;

    mapping(bytes32 => uint256) private _activeRecoveryInitiatorCount;

    // ─── Errors ────────────────────────────────────────────────────────────

    error BeforeGenesis();
    error InvalidEpochConfig();

    error UnknownSession(uint256 session_id);
    error UnknownGhost(bytes32 ghost_id);

    error OnlyGhostWallet();
    error OnlyReceiptManager();

    error InvalidParams();
    error InvalidAmount();

    error ShellNotBonded(bytes32 shell_id);

    error SessionNotActive(bytes32 ghost_id);
    error SessionInRecovery(bytes32 ghost_id);
    error SessionExpired(bytes32 ghost_id);

    error TrustRefreshRequired(bytes32 ghost_id);

    error MigrationPending(bytes32 ghost_id);
    error NoPendingMigration(bytes32 ghost_id);
    error MigrationExpired(bytes32 ghost_id, uint256 now_epoch, uint256 mig_expiry_epoch);
    error MigrationDestMismatch(bytes32 expected, bytes32 provided);
    error MissingStagingSession(bytes32 ghost_id);
    error BadMigrationProof(bytes32 expected, bytes32 provided);

    error RecoveryNotAllowed(bytes32 ghost_id);
    error RecoveryNotActive(bytes32 ghost_id, uint64 attempt_id);
    error RecoveryTimeoutNotReached(uint256 now_epoch, uint256 required_epoch);
    error RecoveryTakeoverNotReached(uint256 now_epoch, uint256 required_epoch);

    error NotEnoughVerifierSignatures(uint256 provided, uint256 required);
    error MeasurementNotAllowed(bytes32 measurement_hash);
    error InvalidRBC();

    error NotEnoughRecoverySignatures(uint256 provided, uint256 required);
    error BadRecoverySetHash(bytes32 provided, bytes32 expected);

    error NotEnoughShareReceipts(uint256 provided, uint256 required);

    error CooldownNotElapsed(uint256 now_epoch, uint256 required_epoch);
    error TECFailed(bytes32 ghost_id);

    error EthTransferFailed();

    // ─── Init Params ───────────────────────────────────────────────────────

    struct InitParams {
        uint256 genesis_time;
        uint256 epoch_len;
        uint256 lease_default;
        uint256 t_trust_refresh;
        uint256 t_recovery_timeout;
        uint256 t_recovery_takeover;
        uint256 t_recovery_cooldown;
        uint256 b_start;
        uint8 passport_filters;
        uint256 c_passport;
        uint256 bloom_m_bits;
        uint8 bloom_k_hashes;
        uint256 t_migration_timeout;
        uint64 k_verifier_threshold;
        address ghost_registry;
        address shell_registry;
        address receipt_manager;
        address verifier_registry;
    }

    constructor(InitParams memory p) {
        if (p.epoch_len == 0) revert InvalidEpochConfig();
        if (p.passport_filters == 0) revert InvalidParams();
        if (p.c_passport == 0) revert InvalidParams();
        if (p.bloom_m_bits == 0) revert InvalidParams();
        if (p.bloom_k_hashes == 0) revert InvalidParams();
        if (p.c_passport % p.passport_filters != 0) revert InvalidParams();
        if (p.ghost_registry == address(0) || p.shell_registry == address(0) || p.receipt_manager == address(0) || p.verifier_registry == address(0)) {
            revert InvalidParams();
        }

        GENESIS_TIME = p.genesis_time;
        EPOCH_LEN = p.epoch_len;

        LEASE_DEFAULT = p.lease_default;
        T_TRUST_REFRESH = p.t_trust_refresh;

        T_RECOVERY_TIMEOUT = p.t_recovery_timeout;
        T_RECOVERY_TAKEOVER = p.t_recovery_takeover;
        T_RECOVERY_COOLDOWN = p.t_recovery_cooldown;

        B_START = p.b_start;

        B_PASSPORT_FILTERS = p.passport_filters;
        C_PASSPORT = p.c_passport;
        BLOOM_M_BITS = p.bloom_m_bits;
        BLOOM_K_HASHES = p.bloom_k_hashes;

        T_MIGRATION_TIMEOUT = p.t_migration_timeout;
        K_VERIFIER_THRESHOLD = p.k_verifier_threshold;

        GHOST_REGISTRY = IGhostRegistry(p.ghost_registry);
        SHELL_REGISTRY = IShellRegistry(p.shell_registry);
        RECEIPT_MANAGER = IReceiptManager(p.receipt_manager);
        VERIFIER_REGISTRY = IVerifierRegistry(p.verifier_registry);

        BLOOM_WORDS = (BLOOM_M_BITS + 255) / 256;
        PASSPORT_ROT_PERIOD = C_PASSPORT / B_PASSPORT_FILTERS;
    }

    // ─── Epoch Helper ──────────────────────────────────────────────────────

    function _currentEpoch() internal view returns (uint256) {
        if (block.timestamp < GENESIS_TIME) revert BeforeGenesis();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    // ─── Session Lifecycle ─────────────────────────────────────────────────

    function openSession(bytes32 ghost_id, bytes32 shell_id, SessionParams calldata params) external override nonReentrant {
        _requireGhostWallet(ghost_id);
        _processExpiryInternal(ghost_id);

        if (params.max_SU == 0 || params.tenure_limit_epochs == 0 || params.asset == address(0)) revert InvalidParams();

        uint256 now_epoch = _currentEpoch();
        uint8 assurance_tier_snapshot = _requireBondedShell(shell_id);

        uint256 lease_expiry = params.lease_expiry_epoch;
        lease_expiry = _computeLeaseExpiry(lease_expiry, now_epoch);

        (bool staging, uint256 parent_id) = _computeStagingOpen(ghost_id, shell_id, now_epoch);
        uint256 residency_start_epoch = _computeResidencyStartEpoch(ghost_id, shell_id, now_epoch, staging);

        bool passport_bonus_applies = _computePassportBonusApplies(ghost_id, shell_id, now_epoch, staging);

        uint256 session_id = _nextSessionId++;
        SessionState storage s = _sessions[session_id];
        s.session_id = session_id;
        s.ghost_id = ghost_id;
        s.shell_id = shell_id;
        s.mode = uint8(SessionMode.NORMAL);
        s.stranded_reason = uint8(StrandedReason.NO_SESSION);
        s.lease_expiry_epoch = lease_expiry;
        s.residency_start_epoch = residency_start_epoch;
        s.residency_start_epoch_snapshot = residency_start_epoch;
        s.residency_tenure_limit_epochs = params.tenure_limit_epochs;
        s.session_start_epoch = now_epoch;
        s.pricing_mode = 0;
        s.assurance_tier_snapshot = assurance_tier_snapshot;
        s.staging = staging;
        s.passport_bonus_applies = passport_bonus_applies;
        s.pending_migration = false;
        s.mig_dest_shell_id = bytes32(0);
        s.mig_dest_session_id = 0;
        s.mig_expiry_epoch = 0;

        _paramsBySession[session_id] = params;
        _sessionExists[session_id] = true;

        if (staging) {
            _sessions[parent_id].mig_dest_session_id = session_id;
            _stagingParentSession[session_id] = parent_id;
        } else {
            _activeSessionIdByGhost[ghost_id] = session_id;
        }

        _lastSessionIdByGhost[ghost_id] = session_id;

        // Initialize trust refresh baseline on first-ever session open (prevents epoch 0 sentinel ambiguity).
        if (_lastTrustRefreshEpochPlusOneByGhost[ghost_id] == 0) {
            _lastTrustRefreshEpochPlusOneByGhost[ghost_id] = now_epoch + 1;
        }

        emit SessionOpened(ghost_id, shell_id, session_id);
    }

    function renewLease(bytes32 ghost_id) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        _processExpiryInternal(ghost_id);

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.NORMAL)) revert SessionExpired(ghost_id);
        if (s.staging) revert InvalidParams();

        uint256 now_epoch = _currentEpoch();

        // Enforce tenure expiry.
        uint256 tenure_expiry = s.residency_start_epoch_snapshot + s.residency_tenure_limit_epochs;
        if (now_epoch >= tenure_expiry) revert SessionExpired(ghost_id);

        // Enforce lease expiry (must renew before expiry).
        if (now_epoch >= s.lease_expiry_epoch) revert SessionExpired(ghost_id);

        // Trust refresh: if last refresh is too old and we're not on an anchor, revert.
        uint256 last_refresh_epoch = 0;
        uint256 last_refresh_plus_one = _lastTrustRefreshEpochPlusOneByGhost[ghost_id];
        if (last_refresh_plus_one != 0) last_refresh_epoch = last_refresh_plus_one - 1;

        bool anchors_configured = _anchorsConfigured(g);
        bool on_anchor = isRefreshAnchor(ghost_id, s.shell_id);

        if (anchors_configured) {
            if (now_epoch > last_refresh_epoch + T_TRUST_REFRESH && !on_anchor) revert TrustRefreshRequired(ghost_id);
            if (on_anchor) _lastTrustRefreshEpochPlusOneByGhost[ghost_id] = now_epoch + 1;
        } else {
            // Avoid bricking ghosts with empty anchor configuration.
            emit NoAnchorsConfigured(ghost_id);
            _lastTrustRefreshEpochPlusOneByGhost[ghost_id] = now_epoch + 1;
        }

        s.lease_expiry_epoch = now_epoch + LEASE_DEFAULT;
        emit LeaseRenewed(ghost_id, s.lease_expiry_epoch);
    }

    function closeSession(bytes32 ghost_id) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        _processExpiryInternal(ghost_id);

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.NORMAL)) revert SessionExpired(ghost_id);
        if (s.staging) revert InvalidParams();

        uint256 now_epoch = _currentEpoch();

        _setMode(ghost_id, s, SessionMode.STRANDED);
        s.stranded_reason = uint8(StrandedReason.VOLUNTARY_CLOSE);
        _strandedSinceEpochPlusOneByGhost[ghost_id] = now_epoch + 1;

        _dwellLastEpochPlusOne[ghost_id][s.shell_id] = now_epoch + 1;

        emit SessionClosed(ghost_id, s.shell_id, session_id);
    }

    function fundNextEpoch(uint256 session_id, uint256 amount) external override nonReentrant {
        if (!_sessionExists[session_id]) revert UnknownSession(session_id);
        if (amount == 0) revert InvalidAmount();

        SessionState storage s = _sessions[session_id];
        GhostRecord memory g = GHOST_REGISTRY.getGhost(s.ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        if (s.mode != uint8(SessionMode.NORMAL)) revert SessionExpired(s.ghost_id);

        uint256 now_epoch = _currentEpoch();
        uint256 tenure_expiry = s.residency_start_epoch_snapshot + s.residency_tenure_limit_epochs;
        if (now_epoch >= s.lease_expiry_epoch || now_epoch >= tenure_expiry) revert SessionExpired(s.ghost_id);

        SessionParams storage p = _paramsBySession[session_id];
        IERC20(p.asset).safeTransferFrom(msg.sender, address(this), amount);

        uint256 epoch_to_fund = now_epoch + 1;
        if (!_escrowEpochListed[session_id][epoch_to_fund]) {
            _escrowEpochListed[session_id][epoch_to_fund] = true;
            _escrowEpochListBySession[session_id].push(epoch_to_fund);
        }
        _escrowBySessionByEpoch[session_id][epoch_to_fund] += amount;
    }

    function settleEpoch(uint256 session_id, uint256 epoch, uint256 su_delivered) external override nonReentrant {
        if (msg.sender != address(RECEIPT_MANAGER)) revert OnlyReceiptManager();
        if (!_sessionExists[session_id]) revert UnknownSession(session_id);

        SessionState storage s = _sessions[session_id];
        if (s.staging) revert InvalidParams();

        SessionParams storage p = _paramsBySession[session_id];
        if (su_delivered > p.max_SU) revert InvalidParams();

        uint256 escrow = _escrowBySessionByEpoch[session_id][epoch];
        _escrowBySessionByEpoch[session_id][epoch] = 0;

        uint256 rent = p.price_per_SU * su_delivered;
        uint256 pay = rent;
        if (pay > escrow) pay = escrow;
        uint256 refund = escrow - pay;

        if (pay > 0) {
            address payout = SHELL_REGISTRY.getShell(s.shell_id).payout_address;
            IERC20(p.asset).safeTransfer(payout, pay);
        }
        if (refund > 0) {
            address wallet = GHOST_REGISTRY.getGhost(s.ghost_id).wallet;
            IERC20(p.asset).safeTransfer(wallet, refund);
        }
    }

    // ─── Migration ─────────────────────────────────────────────────────────

    function startMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes32 bundle_hash) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        _processExpiryInternal(ghost_id);

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);
        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.NORMAL)) revert SessionExpired(ghost_id);
        if (s.pending_migration) revert MigrationPending(ghost_id);
        if (s.staging) revert InvalidParams();

        uint256 now_epoch = _currentEpoch();
        s.pending_migration = true;
        s.mig_dest_shell_id = to_shell_id;
        s.mig_dest_session_id = 0;
        s.mig_expiry_epoch = now_epoch + T_MIGRATION_TIMEOUT;
        _migBundleHashByGhost[ghost_id] = bundle_hash;

        emit MigrationStarted(ghost_id, to_shell_id, s.mig_expiry_epoch);
    }

    function cancelMigration(bytes32 ghost_id) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);
        SessionState storage parent = _sessions[session_id];
        if (!parent.pending_migration) revert NoPendingMigration(ghost_id);

        uint256 staging_id = parent.mig_dest_session_id;
        if (staging_id != 0 && _sessionExists[staging_id]) {
            // Refund all escrow held for the staging session.
            SessionParams storage sp = _paramsBySession[staging_id];
            uint256[] storage epochs = _escrowEpochListBySession[staging_id];
            uint256 refund_total = 0;
            for (uint256 i = 0; i < epochs.length; i++) {
                uint256 e = epochs[i];
                uint256 amt = _escrowBySessionByEpoch[staging_id][e];
                if (amt != 0) {
                    _escrowBySessionByEpoch[staging_id][e] = 0;
                    refund_total += amt;
                }
            }
            if (refund_total != 0) {
                IERC20(sp.asset).safeTransfer(g.wallet, refund_total);
            }

            // Close staging session (do NOT write dwell counter for staging).
            SessionState storage staging = _sessions[staging_id];
            if (staging.mode == uint8(SessionMode.NORMAL)) {
                _setMode(ghost_id, staging, SessionMode.STRANDED);
                staging.stranded_reason = uint8(StrandedReason.VOLUNTARY_CLOSE);
                emit SessionClosed(ghost_id, staging.shell_id, staging_id);
            }

            delete _stagingParentSession[staging_id];
        }

        // Clear migration state on parent.
        parent.pending_migration = false;
        parent.mig_dest_shell_id = bytes32(0);
        parent.mig_dest_session_id = 0;
        parent.mig_expiry_epoch = 0;
        delete _migBundleHashByGhost[ghost_id];

        emit MigrationCancelled(ghost_id);
    }

    function finalizeMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes calldata proof) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        uint256 parent_id = _activeSessionIdByGhost[ghost_id];
        if (parent_id == 0) revert UnknownGhost(ghost_id);
        SessionState storage parent = _sessions[parent_id];
        if (!parent.pending_migration) revert NoPendingMigration(ghost_id);
        if (parent.mig_dest_shell_id != to_shell_id) revert MigrationDestMismatch(parent.mig_dest_shell_id, to_shell_id);

        uint256 now_epoch = _currentEpoch();
        if (now_epoch > parent.mig_expiry_epoch) revert MigrationExpired(ghost_id, now_epoch, parent.mig_expiry_epoch);

        bytes32 expected = _migBundleHashByGhost[ghost_id];
        bytes32 provided = keccak256(proof);
        if (expected != provided) revert BadMigrationProof(expected, provided);

        uint256 staging_id = parent.mig_dest_session_id;
        if (staging_id == 0 || !_sessionExists[staging_id]) revert MissingStagingSession(ghost_id);

        SessionState storage staging = _sessions[staging_id];
        if (!staging.staging) revert InvalidParams();
        if (staging.shell_id != to_shell_id) revert MigrationDestMismatch(to_shell_id, staging.shell_id);
        if (staging.mode != uint8(SessionMode.NORMAL)) revert InvalidParams();

        // Close old active session voluntarily (writes dwell counter).
        _closeActiveSessionForMigration(ghost_id, parent, parent_id);

        // Promote staging session.
        staging.staging = false;
        staging.pending_migration = false;
        staging.mig_dest_shell_id = bytes32(0);
        staging.mig_dest_session_id = 0;
        staging.mig_expiry_epoch = 0;

        _activeSessionIdByGhost[ghost_id] = staging_id;

        delete parent.pending_migration;
        parent.mig_dest_shell_id = bytes32(0);
        parent.mig_dest_session_id = 0;
        parent.mig_expiry_epoch = 0;
        delete _migBundleHashByGhost[ghost_id];
        delete _stagingParentSession[staging_id];

        emit MigrationFinalized(ghost_id, to_shell_id, staging_id);
    }

    // ─── Recovery ──────────────────────────────────────────────────────────

    function startRecovery(bytes32 ghost_id) external payable override nonReentrant returns (uint64 attempt_id) {
        if (msg.value < B_START) revert InvalidAmount();

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        _processExpiryInternal(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.NORMAL) && s.mode != uint8(SessionMode.STRANDED)) revert RecoveryNotAllowed(ghost_id);
        if (s.mode == uint8(SessionMode.RECOVERY_LOCKED) || s.mode == uint8(SessionMode.RECOVERY_STABILIZING)) revert RecoveryNotAllowed(ghost_id);

        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        bytes32 initiator_shell_id = _shellIdFromSender(msg.sender);

        // Must be bonded Safe Haven in the Recovery Set.
        if (!_inRecoverySetLive(g, initiator_shell_id)) revert RecoveryNotAllowed(ghost_id);
        ShellRecord memory sh = SHELL_REGISTRY.getShell(initiator_shell_id);
        if (sh.bond_status != uint8(BondStatus.BONDED) || sh.safehaven_bond_amount == 0 || sh.assurance_tier != 3) {
            revert RecoveryNotAllowed(ghost_id);
        }

        attempt_id = ++_nextAttemptIdByGhost[ghost_id];

        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        a.attempt_id = attempt_id;
        a.ghost_id = ghost_id;
        a.initiator_shell_id = initiator_shell_id;
        a.start_epoch = _currentEpoch();
        a.checkpoint_commitment = g.checkpoint_commitment;
        a.envelope_commitment = g.envelope_commitment;
        a.rs_hash = keccak256(abi.encodePacked(g.recovery_config.recovery_set));
        a.t_required = g.recovery_config.threshold;
        a.bounty_snapshot = g.recovery_config.bounty_total;
        a.status = uint8(RecoveryStatus.ACTIVE);

        _activeAttemptIdByGhost[ghost_id] = attempt_id;
        _recoveryBondByGhostById[ghost_id][attempt_id] = msg.value;

        _activeRecoveryInitiatorCount[initiator_shell_id] += 1;

        // Transition session into RECOVERY_LOCKED.
        _setMode(ghost_id, s, SessionMode.RECOVERY_LOCKED);
        s.pricing_mode = 1;

        emit RecoveryStarted(ghost_id, attempt_id, initiator_shell_id);
    }

    function recoveryRotate(
        bytes32 ghost_id,
        uint64 attempt_id,
        bytes calldata new_identity_pubkey,
        RBC calldata rbc,
        bytes32[] calldata rs_list,
        AuthSig[] calldata sigs,
        ShareReceipt[] calldata share_receipts
    ) external override nonReentrant {
        _recoveryRotateVerify(ghost_id, attempt_id, new_identity_pubkey, rbc, rs_list, sigs, share_receipts);
        _recoveryRotateFinalize(ghost_id, attempt_id, new_identity_pubkey);
    }

    function _recoveryRotateVerify(
        bytes32 ghost_id,
        uint64 attempt_id,
        bytes calldata new_identity_pubkey,
        RBC calldata rbc,
        bytes32[] calldata rs_list,
        AuthSig[] calldata sigs,
        ShareReceipt[] calldata share_receipts
    ) internal view {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.RECOVERY_LOCKED)) revert RecoveryNotAllowed(ghost_id);

        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        if (a.attempt_id != attempt_id || a.status != uint8(RecoveryStatus.ACTIVE)) revert RecoveryNotActive(ghost_id, attempt_id);

        _verifyRBC(a, new_identity_pubkey, rbc);
        _verifyRecoverySetHash(a, rs_list);
        _verifyAuthSigs(a, new_identity_pubkey, rs_list, sigs);
        _verifyShareReceipts(a, rs_list, share_receipts);
    }

    function _recoveryRotateFinalize(bytes32 ghost_id, uint64 attempt_id, bytes calldata new_identity_pubkey) internal {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.RECOVERY_LOCKED)) revert RecoveryNotAllowed(ghost_id);

        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        if (a.attempt_id != attempt_id || a.status != uint8(RecoveryStatus.ACTIVE)) revert RecoveryNotActive(ghost_id, attempt_id);

        // Rotate identity key via GhostRegistry (recovery path allows empty proof).
        GHOST_REGISTRY.rotateSigner(ghost_id, new_identity_pubkey, "");

        a.status = uint8(RecoveryStatus.ROTATED);
        _recoveryRotatedEpochPlusOneByGhostById[ghost_id][attempt_id] = _currentEpoch() + 1;

        // Transition mode: RECOVERY_LOCKED -> RECOVERY_STABILIZING.
        _setMode(ghost_id, s, SessionMode.RECOVERY_STABILIZING);

        // Pay rescue bounty via GhostWallet.
        IGhostWallet(GHOST_REGISTRY.getGhost(ghost_id).wallet).payRescueBounty(ghost_id, attempt_id);

        // Refund initiator bond.
        _refundRecoveryBond(ghost_id, attempt_id, a.initiator_shell_id);

        emit RecoveryRotated(ghost_id, attempt_id);
    }

    function expireRecovery(bytes32 ghost_id) external override nonReentrant {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.RECOVERY_LOCKED)) revert RecoveryNotAllowed(ghost_id);

        uint64 attempt_id = _activeAttemptIdByGhost[ghost_id];
        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        if (a.status != uint8(RecoveryStatus.ACTIVE)) revert RecoveryNotActive(ghost_id, attempt_id);

        uint256 now_epoch = _currentEpoch();
        uint256 required_epoch = a.start_epoch + T_RECOVERY_TIMEOUT;
        if (now_epoch < required_epoch) revert RecoveryTimeoutNotReached(now_epoch, required_epoch);

        a.status = uint8(RecoveryStatus.EXPIRED);

        _setMode(ghost_id, s, SessionMode.STRANDED);
        s.pricing_mode = 0;
        s.stranded_reason = uint8(StrandedReason.EXPIRED);
        _strandedSinceEpochPlusOneByGhost[ghost_id] = now_epoch + 1;

        _refundRecoveryBond(ghost_id, attempt_id, a.initiator_shell_id);

        emit RecoveryExpired(ghost_id, attempt_id);
    }

    function takeoverRecovery(bytes32 ghost_id) external payable override nonReentrant {
        if (msg.value < B_START) revert InvalidAmount();

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.RECOVERY_LOCKED)) revert RecoveryNotAllowed(ghost_id);

        uint64 attempt_id = _activeAttemptIdByGhost[ghost_id];
        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        if (a.status != uint8(RecoveryStatus.ACTIVE)) revert RecoveryNotActive(ghost_id, attempt_id);

        uint256 now_epoch = _currentEpoch();
        uint256 required_epoch = a.start_epoch + T_RECOVERY_TAKEOVER;
        if (now_epoch < required_epoch) revert RecoveryTakeoverNotReached(now_epoch, required_epoch);

        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        bytes32 new_initiator = _shellIdFromSender(msg.sender);

        // v1 choice: takeover checks live RS membership (conservative vs snapshot).
        if (!_inRecoverySetLive(g, new_initiator)) revert RecoveryNotAllowed(ghost_id);
        ShellRecord memory sh = SHELL_REGISTRY.getShell(new_initiator);
        if (sh.bond_status != uint8(BondStatus.BONDED) || sh.safehaven_bond_amount == 0 || sh.assurance_tier != 3) {
            revert RecoveryNotAllowed(ghost_id);
        }

        // Refund existing initiator bond and swap initiator.
        _refundRecoveryBond(ghost_id, attempt_id, a.initiator_shell_id);

        // Update active initiator counts.
        // Note: _refundRecoveryBond already decremented the old initiator count.
        _activeRecoveryInitiatorCount[new_initiator] += 1;

        a.initiator_shell_id = new_initiator;
        a.start_epoch = now_epoch; // reset timeout windows
        _recoveryBondByGhostById[ghost_id][attempt_id] = msg.value;
    }

    function exitRecovery(bytes32 ghost_id) external override nonReentrant {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        if (msg.sender != g.wallet) revert OnlyGhostWallet();

        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.RECOVERY_STABILIZING)) revert RecoveryNotAllowed(ghost_id);

        uint64 attempt_id = _activeAttemptIdByGhost[ghost_id];
        RecoveryAttempt storage a = _recoveryAttemptByGhostById[ghost_id][attempt_id];
        if (a.status != uint8(RecoveryStatus.ROTATED)) revert RecoveryNotAllowed(ghost_id);

        uint256 rotated_plus_one = _recoveryRotatedEpochPlusOneByGhostById[ghost_id][attempt_id];
        if (rotated_plus_one == 0) revert RecoveryNotAllowed(ghost_id);
        uint256 rotated_epoch = rotated_plus_one - 1;

        uint256 now_epoch = _currentEpoch();
        uint256 required_epoch = rotated_epoch + T_RECOVERY_COOLDOWN;
        if (now_epoch < required_epoch) revert CooldownNotElapsed(now_epoch, required_epoch);

        if (!_verifyTEC(ghost_id, s.shell_id, g.wallet)) revert TECFailed(ghost_id);

        _setMode(ghost_id, s, SessionMode.NORMAL);
        s.pricing_mode = 0;

        emit RecoveryExited(ghost_id);
    }

    function proveSafeHavenEquivocation(
        bytes32 shell_id,
        bytes32 ghost_id,
        uint64 attempt_id,
        bytes32 checkpoint_commitment,
        bytes calldata pk_new_a,
        bytes calldata sig_a,
        bytes calldata pk_new_b,
        bytes calldata sig_b
    ) external override nonReentrant {
        if (keccak256(pk_new_a) == keccak256(pk_new_b)) revert InvalidParams();

        bytes32 d_a = _recoverAuthDigest(ghost_id, attempt_id, checkpoint_commitment, pk_new_a);
        bytes32 d_b = _recoverAuthDigest(ghost_id, attempt_id, checkpoint_commitment, pk_new_b);

        address expected = address(uint160(uint256(shell_id)));
        if (ECDSA.recover(d_a, sig_a) != expected) revert InvalidParams();
        if (ECDSA.recover(d_b, sig_b) != expected) revert InvalidParams();

        _slashSafeHaven(shell_id);
    }

    function _slashSafeHaven(bytes32 shell_id) internal {
        uint256 amt = SHELL_REGISTRY.getShell(shell_id).safehaven_bond_amount;
        SHELL_REGISTRY.slashSafeHaven(shell_id, amt, msg.sender);
    }

    // ─── Views ─────────────────────────────────────────────────────────────

    function getSession(bytes32 ghost_id) external view override returns (SessionState memory) {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);
        return _virtualizeExpiry(_sessions[session_id]);
    }

    function getSessionById(uint256 session_id) external view override returns (SessionState memory) {
        if (!_sessionExists[session_id]) revert UnknownSession(session_id);
        return _virtualizeExpiry(_sessions[session_id]);
    }

    function getSessionKeys(uint256 session_id) external view override returns (bytes memory ghost_key, bytes memory shell_key, address submitter) {
        if (!_sessionExists[session_id]) revert UnknownSession(session_id);
        SessionParams storage p = _paramsBySession[session_id];
        return (p.ghost_session_key, p.shell_session_key, p.submitter_address);
    }

    function effectiveTenureExpiry(bytes32 ghost_id) external view override returns (uint256) {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) revert UnknownGhost(ghost_id);
        SessionState storage s = _sessions[session_id];
        return s.residency_start_epoch_snapshot + s.residency_tenure_limit_epochs;
    }

    function isRefreshAnchor(bytes32 ghost_id, bytes32 shell_id) public view override returns (bool) {
        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        bytes32 home = IGhostWallet(g.wallet).homeShell(ghost_id);
        if (shell_id == home && home != bytes32(0)) return true;

        bytes32[] memory rs = g.recovery_config.recovery_set;
        for (uint256 i = 0; i < rs.length; i++) {
            if (rs[i] == shell_id) return true;
        }
        return false;
    }

    function isActiveRecoveryInitiator(bytes32 shell_id) external view override returns (bool) {
        return _activeRecoveryInitiatorCount[shell_id] > 0;
    }

    function getRecoveryAttempt(bytes32 ghost_id, uint64 attempt_id) external view override returns (RecoveryAttempt memory) {
        return _recoveryAttemptByGhostById[ghost_id][attempt_id];
    }

    function processExpiry(bytes32 ghost_id) external override nonReentrant {
        _processExpiryInternal(ghost_id);
    }

    // ─── Internal Helpers ───────────────────────────────────────────────────

    function _setMode(bytes32 ghost_id, SessionState storage s, SessionMode new_mode) internal {
        uint8 old = s.mode;
        uint8 next = uint8(new_mode);
        if (old == next) return;
        s.mode = next;
        emit ModeChanged(ghost_id, old, next);
    }

    function _requireGhostWallet(bytes32 ghost_id) internal view {
        address wallet = GHOST_REGISTRY.getGhost(ghost_id).wallet;
        if (msg.sender != wallet) revert OnlyGhostWallet();
    }

    function _requireBondedShell(bytes32 shell_id) internal view returns (uint8 assurance_tier_snapshot) {
        ShellRecord memory sh = SHELL_REGISTRY.getShell(shell_id);
        if (sh.shell_id != shell_id) revert ShellNotBonded(shell_id);
        if (sh.bond_status != uint8(BondStatus.BONDED)) revert ShellNotBonded(shell_id);
        return sh.assurance_tier;
    }

    function _computeLeaseExpiry(uint256 requested_expiry, uint256 now_epoch) internal view returns (uint256) {
        if (requested_expiry == 0) return now_epoch + LEASE_DEFAULT;
        if (requested_expiry <= now_epoch) revert InvalidParams();
        return requested_expiry;
    }

    function _computeStagingOpen(bytes32 ghost_id, bytes32 shell_id, uint256 now_epoch) internal view returns (bool staging, uint256 parent_id) {
        uint256 existing_id = _activeSessionIdByGhost[ghost_id];
        if (existing_id == 0) return (false, 0);

        SessionState storage existing = _sessions[existing_id];
        if (existing.mode == uint8(SessionMode.RECOVERY_LOCKED) || existing.mode == uint8(SessionMode.RECOVERY_STABILIZING)) {
            revert SessionInRecovery(ghost_id);
        }

        if (existing.mode == uint8(SessionMode.NORMAL)) {
            // Allow a staging session open ONLY if a migration is pending to this destination shell.
            if (!existing.pending_migration) revert SessionNotActive(ghost_id);
            if (shell_id != existing.mig_dest_shell_id) revert MigrationDestMismatch(existing.mig_dest_shell_id, shell_id);
            if (existing.mig_dest_session_id != 0) revert MigrationPending(ghost_id);
            if (now_epoch > existing.mig_expiry_epoch) revert MigrationExpired(ghost_id, now_epoch, existing.mig_expiry_epoch);
            return (true, existing_id);
        }

        if (existing.mode == uint8(SessionMode.STRANDED)) return (false, 0);

        revert SessionNotActive(ghost_id);
    }

    function _computeResidencyStartEpoch(bytes32 ghost_id, bytes32 shell_id, uint256 now_epoch, bool staging) internal returns (uint256) {
        if (staging) return now_epoch;

        uint256 last_plus_one = _dwellLastEpochPlusOne[ghost_id][shell_id];
        if (last_plus_one != 0) {
            uint256 last_epoch = last_plus_one - 1;
            uint256 gap = now_epoch - last_epoch;
            if (gap <= 1) {
                uint256 start_plus_one = _residencyStartEpochPlusOneByGhostByShell[ghost_id][shell_id];
                if (start_plus_one != 0) return start_plus_one - 1;
                // Fallback if missing: treat as new residency.
            } else {
                // Lazy prune semantically-dead dwell entry.
                delete _dwellLastEpochPlusOne[ghost_id][shell_id];
            }
        }

        _residencyStartEpochPlusOneByGhostByShell[ghost_id][shell_id] = now_epoch + 1;
        return now_epoch;
    }

    function _computePassportBonusApplies(bytes32 ghost_id, bytes32 shell_id, uint256 now_epoch, bool staging) internal returns (bool) {
        _bloomRotateIfNeeded(ghost_id, now_epoch);
        bool seen_recently = _bloomContains(ghost_id, shell_id);
        bool ghost_eligible = GHOST_REGISTRY.ghostPassportEligible(ghost_id, now_epoch);
        bool passport_bonus_applies = (!seen_recently) && ghost_eligible;
        // V1: skip Bloom insert for staging sessions to prevent pollution on migration cancel.
        if (!staging) _bloomInsert(ghost_id, shell_id);
        return passport_bonus_applies;
    }

    function _processExpiryInternal(bytes32 ghost_id) internal {
        uint256 session_id = _activeSessionIdByGhost[ghost_id];
        if (session_id == 0) return;

        SessionState storage s = _sessions[session_id];
        if (s.mode != uint8(SessionMode.NORMAL)) return;

        uint256 now_epoch = _currentEpoch();
        uint256 tenure_expiry = s.residency_start_epoch_snapshot + s.residency_tenure_limit_epochs;
        uint256 lease_expiry = s.lease_expiry_epoch;

        bool expired = (now_epoch >= lease_expiry) || (now_epoch >= tenure_expiry);
        if (!expired) return;

        uint256 actual_expiry = lease_expiry;
        if (tenure_expiry < actual_expiry) actual_expiry = tenure_expiry;

        _setMode(ghost_id, s, SessionMode.STRANDED);
        s.stranded_reason = uint8(StrandedReason.EXPIRED);
        _strandedSinceEpochPlusOneByGhost[ghost_id] = actual_expiry + 1;
    }

    function _virtualizeExpiry(SessionState storage s) internal view returns (SessionState memory out) {
        out = s;
        if (out.mode != uint8(SessionMode.NORMAL)) return out;
        uint256 now_epoch;
        if (block.timestamp < GENESIS_TIME) return out;
        now_epoch = (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
        uint256 tenure_expiry = out.residency_start_epoch_snapshot + out.residency_tenure_limit_epochs;
        if (now_epoch >= out.lease_expiry_epoch || now_epoch >= tenure_expiry) {
            out.mode = uint8(SessionMode.STRANDED);
            out.stranded_reason = uint8(StrandedReason.EXPIRED);
        }
        return out;
    }

    function _anchorsConfigured(GhostRecord memory g) internal view returns (bool) {
        bytes32 home = IGhostWallet(g.wallet).homeShell(g.ghost_id);
        if (home != bytes32(0)) return true;
        return g.recovery_config.recovery_set.length != 0;
    }

    /// @dev V1 simplification: shell_id = zero-padded operator address.
    ///      In v2, shell_id will be keccak256(TAG_SHELL_ID, identity_pubkey, salt)
    ///      with registry lookups for address resolution.
    function _shellIdFromSender(address sender) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(sender)));
    }

    function _inRecoverySetLive(GhostRecord memory g, bytes32 shell_id) internal pure returns (bool) {
        bytes32[] memory rs = g.recovery_config.recovery_set;
        for (uint256 i = 0; i < rs.length; i++) {
            if (rs[i] == shell_id) return true;
        }
        return false;
    }

    function _verifyTEC(bytes32 ghost_id, bytes32 shell_id, address wallet) internal view returns (bool) {
        IGhostWallet gw = IGhostWallet(wallet);
        bytes32 home = gw.homeShell(ghost_id);
        if (home != bytes32(0) && shell_id == home) return true;

        Policy memory p = gw.getPolicy(ghost_id);
        for (uint256 i = 0; i < p.trusted_shells.length; i++) {
            if (p.trusted_shells[i] == shell_id) return true;
        }

        ShellRecord memory sh = SHELL_REGISTRY.getShell(shell_id);
        if (sh.assurance_tier == 3 && sh.certificate_id != bytes32(0)) return true;

        return false;
    }

    function _closeActiveSessionForMigration(bytes32 ghost_id, SessionState storage s, uint256 session_id) internal {
        uint256 now_epoch = _currentEpoch();
        _setMode(ghost_id, s, SessionMode.STRANDED);
        s.stranded_reason = uint8(StrandedReason.VOLUNTARY_CLOSE);
        _strandedSinceEpochPlusOneByGhost[ghost_id] = now_epoch + 1;
        _dwellLastEpochPlusOne[ghost_id][s.shell_id] = now_epoch + 1;
        emit SessionClosed(ghost_id, s.shell_id, session_id);
    }

    function _refundRecoveryBond(bytes32 ghost_id, uint64 attempt_id, bytes32 initiator_shell_id) internal {
        uint256 amt = _recoveryBondByGhostById[ghost_id][attempt_id];
        if (amt == 0) return;

        delete _recoveryBondByGhostById[ghost_id][attempt_id];

        // Mark initiator as no longer active.
        if (_activeRecoveryInitiatorCount[initiator_shell_id] != 0) {
            _activeRecoveryInitiatorCount[initiator_shell_id] -= 1;
        }

        address to = address(uint160(uint256(initiator_shell_id)));
        (bool ok, ) = to.call{value: amt}("");
        if (!ok) revert EthTransferFailed();
    }

    // ─── Bloom Ring ─────────────────────────────────────────────────────────

    function _bloomRotateIfNeeded(bytes32 ghost_id, uint256 now_epoch) internal {
        uint256 rot_num = now_epoch / PASSPORT_ROT_PERIOD;
        if (!_bloomInit[ghost_id]) {
            _bloomInit[ghost_id] = true;
            _bloomRotNum[ghost_id] = rot_num;
            _bloomHead[ghost_id] = 0;
            return;
        }

        uint256 last = _bloomRotNum[ghost_id];
        if (rot_num <= last) return;

        uint256 diff = rot_num - last;
        if (diff > B_PASSPORT_FILTERS) diff = B_PASSPORT_FILTERS;

        uint8 head = _bloomHead[ghost_id];
        for (uint256 i = 0; i < diff; i++) {
            head = uint8((uint256(head) + 1) % B_PASSPORT_FILTERS);
            _bloomClearFilter(ghost_id, head);
            last += 1;
        }

        _bloomHead[ghost_id] = head;
        _bloomRotNum[ghost_id] = rot_num;
    }

    function _bloomClearFilter(bytes32 ghost_id, uint8 filter_idx) internal {
        for (uint256 w = 0; w < BLOOM_WORDS; w++) {
            _bloomWord[ghost_id][filter_idx][w] = 0;
        }
    }

    function _bloomContains(bytes32 ghost_id, bytes32 shell_id) internal view returns (bool) {
        bytes32 base = keccak256(abi.encode(TAG_BLOOM, ghost_id, shell_id));
        for (uint8 k = 0; k < BLOOM_K_HASHES; k++) {
            uint256 bit = uint256(keccak256(abi.encode(base, k))) % BLOOM_M_BITS;
            uint256 word_index = bit / 256;
            uint256 bit_index = bit % 256;
            uint256 mask = (uint256(1) << bit_index);

            bool any = false;
            for (uint8 f = 0; f < B_PASSPORT_FILTERS; f++) {
                if ((_bloomWord[ghost_id][f][word_index] & mask) != 0) {
                    any = true;
                    break;
                }
            }
            if (!any) return false;
        }
        return true;
    }

    function _bloomInsert(bytes32 ghost_id, bytes32 shell_id) internal {
        bytes32 base = keccak256(abi.encode(TAG_BLOOM, ghost_id, shell_id));
        uint8 head = _bloomHead[ghost_id];
        for (uint8 k = 0; k < BLOOM_K_HASHES; k++) {
            uint256 bit = uint256(keccak256(abi.encode(base, k))) % BLOOM_M_BITS;
            uint256 word_index = bit / 256;
            uint256 bit_index = bit % 256;
            uint256 mask = (uint256(1) << bit_index);
            _bloomWord[ghost_id][head][word_index] |= mask;
        }
    }

    // ─── Recovery Verification ─────────────────────────────────────────────

    function _verifyRBC(RecoveryAttempt storage a, bytes calldata new_identity_pubkey, RBC calldata rbc) internal view {
        if (rbc.ghost_id != a.ghost_id) revert InvalidRBC();
        if (rbc.attempt_id != a.attempt_id) revert InvalidRBC();
        if (rbc.checkpoint_commitment != a.checkpoint_commitment) revert InvalidRBC();
        if (keccak256(rbc.pk_new) != keccak256(new_identity_pubkey)) revert InvalidRBC();
        if (block.timestamp > rbc.valid_to) revert InvalidRBC();

        if (!VERIFIER_REGISTRY.isMeasurementAllowed(rbc.measurement_hash, 1)) revert MeasurementNotAllowed(rbc.measurement_hash);

        bytes32 digest = keccak256(
            abi.encode(
                TAG_RBC,
                rbc.ghost_id,
                rbc.attempt_id,
                rbc.checkpoint_commitment,
                keccak256(rbc.pk_new),
                keccak256(rbc.pk_transport),
                rbc.measurement_hash,
                rbc.tcb_min,
                rbc.valid_to
            )
        );

        uint256 required = uint256(K_VERIFIER_THRESHOLD);
        if (required == 0) return;

        uint256 unique = 0;
        // We only care about reaching the threshold, so cap tracking array to `required`.
        address[] memory seen = new address[](required);
        for (uint256 i = 0; i < rbc.sigs_verifiers.length; i++) {
            address signer = ECDSA.recover(digest, rbc.sigs_verifiers[i]);
            if (!VERIFIER_REGISTRY.isActiveVerifier(signer)) continue;
            if (_containsAddress(seen, unique, signer)) continue;
            if (unique < required) {
                seen[unique] = signer;
                unique += 1;
                if (unique >= required) break;
            }
        }

        if (unique < required) revert NotEnoughVerifierSignatures(unique, required);
    }

    function _verifyRecoverySetHash(RecoveryAttempt storage a, bytes32[] calldata rs_list) internal view {
        bytes32 h = keccak256(abi.encodePacked(rs_list));
        if (h != a.rs_hash) revert BadRecoverySetHash(h, a.rs_hash);
    }

    function _verifyAuthSigs(
        RecoveryAttempt storage a,
        bytes calldata new_identity_pubkey,
        bytes32[] calldata rs_list,
        AuthSig[] calldata sigs
    ) internal view {
        bytes32 digest = keccak256(abi.encode(TAG_RECOVER_AUTH, block.chainid, a.ghost_id, a.attempt_id, a.checkpoint_commitment, keccak256(new_identity_pubkey)));

        uint256 required = uint256(a.t_required);
        if (required == 0) return;

        // Track unique RS member approvals using a dynamic bitset keyed by rs_list index.
        uint256[] memory used = new uint256[]((rs_list.length + 255) / 256);

        uint256 unique = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            bytes32 sh = sigs[i].shell_id;
            (bool found, uint256 idx) = _indexOf(rs_list, sh);
            if (!found) continue;

            address expected = address(uint160(uint256(sh)));
            if (ECDSA.recover(digest, sigs[i].signature) != expected) continue;

            uint256 w = idx / 256;
            uint256 bit = idx % 256;
            uint256 mask = (uint256(1) << bit);
            if ((used[w] & mask) != 0) continue;
            used[w] |= mask;

            unique += 1;
            if (unique >= required) break;
        }

        if (unique < required) revert NotEnoughRecoverySignatures(unique, required);
    }

    function _verifyShareReceipts(RecoveryAttempt storage a, bytes32[] calldata rs_list, ShareReceipt[] calldata receipts) internal view {
        bytes32 d1 = keccak256(abi.encode(TAG_SHARE, block.chainid, a.ghost_id, a.attempt_id, a.checkpoint_commitment, a.envelope_commitment));
        bytes32 d2 = keccak256(abi.encode(TAG_SHARE_ACK, block.chainid, a.ghost_id, a.attempt_id, a.checkpoint_commitment, a.envelope_commitment));

        uint256 required = uint256(a.t_required);
        if (required == 0) return;

        uint256[] memory used = new uint256[]((rs_list.length + 255) / 256);
        uint256 unique = 0;
        for (uint256 i = 0; i < receipts.length; i++) {
            bytes32 sh = receipts[i].shell_id;
            (bool found, uint256 idx) = _indexOf(rs_list, sh);
            if (!found) continue;

            address expected = address(uint160(uint256(sh)));
            if (ECDSA.recover(d1, receipts[i].sig_shell) != expected) continue;
            if (ECDSA.recover(d2, receipts[i].sig_ack) != expected) continue;

            uint256 w = idx / 256;
            uint256 bit = idx % 256;
            uint256 mask = (uint256(1) << bit);
            if ((used[w] & mask) != 0) continue;
            used[w] |= mask;

            unique += 1;
            if (unique >= required) break;
        }

        if (unique < required) revert NotEnoughShareReceipts(unique, required);
    }

    function _recoverAuthDigest(bytes32 ghost_id, uint64 attempt_id, bytes32 checkpoint_commitment, bytes calldata pk_new) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_RECOVER_AUTH, block.chainid, ghost_id, attempt_id, checkpoint_commitment, keccak256(pk_new)));
    }

    function _inBytes32Array(bytes32[] calldata arr, bytes32 x) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == x) return true;
        }
        return false;
    }

    function _indexOf(bytes32[] calldata arr, bytes32 x) internal pure returns (bool found, uint256 idx) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == x) return (true, i);
        }
        return (false, 0);
    }

    function _containsAddress(address[] memory arr, uint256 n, address x) internal pure returns (bool) {
        for (uint256 i = 0; i < n; i++) {
            if (arr[i] == x) return true;
        }
        return false;
    }
}
