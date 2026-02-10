// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGhostWallet} from "./interfaces/IGhostWallet.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IShellRegistry} from "./interfaces/IShellRegistry.sol";
import {IGhostRegistry} from "./interfaces/IGhostRegistry.sol";

import {
    Policy,
    PolicyDelta,
    SessionParams,
    SessionState,
    GhostRecord,
    ShellRecord,
    RecoveryConfig,
    RecoveryAttempt
} from "./types/GITSTypes.sol";

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

/// @dev Minimal clock interface for pulling epoch params from SessionManager.
interface IEpochClock {
    function GENESIS_TIME() external view returns (uint256);
    function EPOCH_LEN() external view returns (uint256);
}

/// @title GhostWallet
/// @notice User-facing entry point for Ghost protocol actions with on-chain policy enforcement (Section 14.3).
contract GhostWallet is IGhostWallet, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ─── Config / Dependencies ─────────────────────────────────────────────

    uint256 public immutable T_POLICY_TIMELOCK; // epochs

    ISessionManager public immutable SESSION_MANAGER;
    IShellRegistry public immutable SHELL_REGISTRY;
    IGhostRegistry public immutable GHOST_REGISTRY;

    // ─── Storage ──────────────────────────────────────────────────────────

    mapping(bytes32 => Policy) internal _policy;
    mapping(bytes32 => address) public wallet_owner;

    // Last known session payment asset (from openSession params).
    mapping(bytes32 => address) internal _assetByGhost;

    // spent tracking (lazy reset by epoch)
    mapping(bytes32 => uint256) internal _spent;
    mapping(bytes32 => uint256) internal _spentEpoch;

    // Proposals
    mapping(bytes32 => uint256) internal _policyNonce;

    enum PendingKind {
        NONE,
        POLICY,
        GUARDIANS
    }

    struct PendingPolicyChange {
        PendingKind kind;
        uint256 executable_at_epoch;
        bytes data; // abi.encode(PolicyDelta) or abi.encode(bytes[] guardians, uint64 t_guardian)
    }

    mapping(bytes32 => mapping(bytes32 => PendingPolicyChange)) internal _pending;

    // Recovery bounty guard
    mapping(bytes32 => mapping(uint64 => bool)) internal _bountyPaid;

    // ─── Events ────────────────────────────────────────────────────────────

    event PolicyChangeProposed(bytes32 indexed ghost_id, bytes32 proposal_id, uint256 executable_at);
    event PolicyChangeExecuted(bytes32 indexed ghost_id, bytes32 proposal_id);
    event PolicyChangeCancelled(bytes32 indexed ghost_id, bytes32 proposal_id);
    event GuardiansUpdated(bytes32 indexed ghost_id, uint64 t_guardian);

    // ─── Errors ────────────────────────────────────────────────────────────

    error NotOwner(bytes32 ghost_id, address caller);
    error OnlySessionManager();

    error InvalidDelta();
    error MixedDelta();
    error NoPendingProposal(bytes32 ghost_id, bytes32 proposal_id);
    error TimelockNotElapsed(uint256 now_epoch, uint256 required_epoch);

    error TECFailed(bytes32 ghost_id);

    error ShellNotAllowed(bytes32 ghost_id, bytes32 shell_id);

    error HotAllowanceExceeded(uint256 spent, uint256 amount, uint256 allowance);
    error EscapeReserveViolation();

    error InvalidPolicy();
    error DuplicateEntry();
    error NotFound(bytes32 id);

    error RescueAlreadyPaid(bytes32 ghost_id, uint64 attempt_id);

    // ─── Init ──────────────────────────────────────────────────────────────

    constructor(address sessionManager_, address shellRegistry_, address ghostRegistry_, uint256 tPolicyTimelock_) {
        SESSION_MANAGER = ISessionManager(sessionManager_);
        SHELL_REGISTRY = IShellRegistry(shellRegistry_);
        GHOST_REGISTRY = IGhostRegistry(ghostRegistry_);
        T_POLICY_TIMELOCK = tPolicyTimelock_;
    }

    receive() external payable {}

    // ─── Registration Helper (v1 convenience; not part of IGhostWallet) ────

    /// @notice Register a new Ghost in GhostRegistry and initialize owner + policy.
    /// @dev Convenience for v1/testing: ensures wallet_owner is set at registration time.
    function registerGhost(
        bytes32 ghost_id,
        bytes calldata identity_pubkey,
        bytes32 salt,
        RecoveryConfig calldata recoveryConfig,
        Policy calldata initialPolicy
    ) external {
        if (wallet_owner[ghost_id] != address(0)) revert InvalidPolicy();

        // GhostRegistry enforces msg.sender == wallet; the wallet is this contract.
        GHOST_REGISTRY.registerGhost(ghost_id, identity_pubkey, address(this), salt, recoveryConfig);

        wallet_owner[ghost_id] = msg.sender;
        _setPolicy(ghost_id, initialPolicy);

        // escape_stable MUST include B_rescue_total.
        if (initialPolicy.escape_stable < recoveryConfig.bounty_total) revert InvalidPolicy();
    }

    // ─── Views ─────────────────────────────────────────────────────────────

    function getPolicy(bytes32 ghost_id) external view override returns (Policy memory) {
        return _policy[ghost_id];
    }

    function homeShell(bytes32 ghost_id) external view override returns (bytes32) {
        return _policy[ghost_id].home_shell;
    }

    function isAllowedShell(bytes32 ghost_id, bytes32 shell_id) public view override returns (bool) {
        bytes32[] storage a = _policy[ghost_id].allowed_shells;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i] == shell_id) return true;
        }
        return false;
    }

    function escapeReserve(bytes32 ghost_id) external view override returns (uint256 escape_gas, uint256 escape_stable) {
        Policy storage p = _policy[ghost_id];
        return (p.escape_gas, p.escape_stable);
    }

    function hotAllowance(bytes32 ghost_id) external view override returns (uint256) {
        return _policy[ghost_id].hot_allowance;
    }

    function spentThisEpoch(bytes32 ghost_id) external view override returns (uint256) {
        uint256 now_epoch = _currentEpoch();
        if (_spentEpoch[ghost_id] != now_epoch) return 0;
        return _spent[ghost_id];
    }

    // ─── Policy Changes ────────────────────────────────────────────────────

    enum ChangeKind {
        NONE,
        TIGHTENING,
        LOOSENING,
        MIXED
    }

    function proposePolicyChange(bytes32 ghost_id, PolicyDelta calldata delta) external override returns (bytes32 proposal_id) {
        _onlyOwner(ghost_id);

        uint256 now_epoch = _currentEpoch();
        proposal_id = keccak256(abi.encode(ghost_id, delta, block.timestamp, _policyNonce[ghost_id]++));

        ChangeKind kind = _classifyPolicyDeltaCalldata(ghost_id, delta);
        if (kind == ChangeKind.NONE) revert InvalidDelta();
        if (kind == ChangeKind.MIXED) revert MixedDelta();

        if (kind == ChangeKind.TIGHTENING) {
            PolicyDelta memory d = delta;
            _applyPolicyDelta(ghost_id, d);
            emit PolicyChangeExecuted(ghost_id, proposal_id);
            return proposal_id;
        }

        // Loosening: timelocked + TEC required at execution time.
        PendingPolicyChange storage pend = _pending[ghost_id][proposal_id];
        pend.kind = PendingKind.POLICY;
        pend.executable_at_epoch = now_epoch + T_POLICY_TIMELOCK;
        pend.data = abi.encode(delta);

        emit PolicyChangeProposed(ghost_id, proposal_id, pend.executable_at_epoch);
        return proposal_id;
    }

    function executePolicyChange(bytes32 ghost_id, bytes32 proposal_id) external override {
        _onlyOwner(ghost_id);

        PendingPolicyChange storage pend = _pending[ghost_id][proposal_id];
        if (pend.kind == PendingKind.NONE) revert NoPendingProposal(ghost_id, proposal_id);

        uint256 now_epoch = _currentEpoch();
        if (now_epoch < pend.executable_at_epoch) revert TimelockNotElapsed(now_epoch, pend.executable_at_epoch);

        if (!_verifyTEC(ghost_id)) revert TECFailed(ghost_id);

        if (pend.kind == PendingKind.POLICY) {
            PolicyDelta memory d = abi.decode(pend.data, (PolicyDelta));
            ChangeKind kind = _classifyPolicyDeltaMemory(ghost_id, d);
            if (kind == ChangeKind.MIXED) revert MixedDelta();
            _applyPolicyDelta(ghost_id, d);
        } else if (pend.kind == PendingKind.GUARDIANS) {
            (bytes[] memory guardians, uint64 t_guardian) = abi.decode(pend.data, (bytes[], uint64));
            ChangeKind kind = _classifyGuardiansChangeMemory(ghost_id, guardians, t_guardian);
            if (kind == ChangeKind.MIXED) revert MixedDelta();
            _applyGuardians(ghost_id, guardians, t_guardian);
        } else {
            revert InvalidDelta();
        }

        delete _pending[ghost_id][proposal_id];
        emit PolicyChangeExecuted(ghost_id, proposal_id);
    }

    function cancelPolicyChange(bytes32 ghost_id, bytes32 proposal_id) external override {
        _onlyOwner(ghost_id);
        PendingPolicyChange storage pend = _pending[ghost_id][proposal_id];
        if (pend.kind == PendingKind.NONE) revert NoPendingProposal(ghost_id, proposal_id);
        delete _pending[ghost_id][proposal_id];
        emit PolicyChangeCancelled(ghost_id, proposal_id);
    }

    // ─── Tightening Helpers ────────────────────────────────────────────────

    function removeTrustedShell(bytes32 ghost_id, bytes32 shell_id) external override {
        _onlyOwner(ghost_id);
        Policy storage p = _policy[ghost_id];
        _removeBytes32(p.trusted_shells, shell_id);
    }

    function removeAllowedShell(bytes32 ghost_id, bytes32 shell_id) external override {
        _onlyOwner(ghost_id);
        Policy storage p = _policy[ghost_id];
        if (shell_id == p.home_shell && p.home_shell != bytes32(0)) revert InvalidPolicy();
        _removeBytes32(p.allowed_shells, shell_id);
        _removeBytes32IfPresent(p.trusted_shells, shell_id);
    }

    // ─── Protocol Actions ──────────────────────────────────────────────────

    function openSession(bytes32 ghost_id, bytes32 shell_id, SessionParams calldata params) external override {
        _onlyOwner(ghost_id);
        _requireAllowedOrRoaming(ghost_id, shell_id);

        _assetByGhost[ghost_id] = params.asset;
        IERC20(params.asset).forceApprove(address(SESSION_MANAGER), type(uint256).max);

        SESSION_MANAGER.openSession(ghost_id, shell_id, params);
    }

    function renewLease(bytes32 ghost_id) external override {
        _onlyOwner(ghost_id);
        SESSION_MANAGER.renewLease(ghost_id);
    }

    function closeSession(bytes32 ghost_id) external override {
        _onlyOwner(ghost_id);
        SESSION_MANAGER.closeSession(ghost_id);
    }

    function fundNextEpoch(bytes32 ghost_id, uint256 amount) external override {
        _onlyOwner(ghost_id);
        _enforceSpend(ghost_id, amount);

        SessionState memory s = SESSION_MANAGER.getSession(ghost_id);
        SESSION_MANAGER.fundNextEpoch(s.session_id, amount);
    }

    function startMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes32 bundle_hash) external override {
        _onlyOwner(ghost_id);
        _requireAllowedOrRoaming(ghost_id, to_shell_id);
        SESSION_MANAGER.startMigration(ghost_id, to_shell_id, bundle_hash);
    }

    function cancelMigration(bytes32 ghost_id) external override {
        _onlyOwner(ghost_id);
        SESSION_MANAGER.cancelMigration(ghost_id);
    }

    function finalizeMigration(bytes32 ghost_id, bytes32 to_shell_id, bytes calldata proof) external override {
        _onlyOwner(ghost_id);
        SESSION_MANAGER.finalizeMigration(ghost_id, to_shell_id, proof);
    }

    // ─── Guardian Management ───────────────────────────────────────────────

    function setGuardians(bytes32 ghost_id, bytes[] calldata guardians, uint64 t_guardian) external override {
        _onlyOwner(ghost_id);

        ChangeKind kind = _classifyGuardiansChangeCalldata(ghost_id, guardians, t_guardian);
        if (kind == ChangeKind.NONE) revert InvalidDelta();
        if (kind == ChangeKind.MIXED) revert MixedDelta();

        if (kind == ChangeKind.TIGHTENING) {
            _applyGuardians(ghost_id, guardians, t_guardian);
            return;
        }

        // Loosening: timelocked + TEC required.
        uint256 now_epoch = _currentEpoch();
        bytes32 proposal_id = keccak256(abi.encode(ghost_id, guardians, t_guardian, block.timestamp, _policyNonce[ghost_id]++));

        PendingPolicyChange storage pend = _pending[ghost_id][proposal_id];
        pend.kind = PendingKind.GUARDIANS;
        pend.executable_at_epoch = now_epoch + T_POLICY_TIMELOCK;
        pend.data = abi.encode(guardians, t_guardian);

        emit PolicyChangeProposed(ghost_id, proposal_id, pend.executable_at_epoch);
    }

    // ─── Recovery ──────────────────────────────────────────────────────────

    function payRescueBounty(bytes32 ghost_id, uint64 attempt_id) external override nonReentrant {
        if (msg.sender != address(SESSION_MANAGER)) revert OnlySessionManager();
        if (_bountyPaid[ghost_id][attempt_id]) revert RescueAlreadyPaid(ghost_id, attempt_id);

        RecoveryAttempt memory a = SESSION_MANAGER.getRecoveryAttempt(ghost_id, attempt_id);
        if (a.attempt_id != attempt_id) revert InvalidDelta();

        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        address stable = g.recovery_config.bounty_asset;
        uint256 bounty = a.bounty_snapshot;

        _bountyPaid[ghost_id][attempt_id] = true;

        if (bounty == 0) return;
        if (stable == address(0)) revert InvalidPolicy();

        Policy storage p = _policy[ghost_id];
        if (p.escape_stable < bounty) revert EscapeReserveViolation();

        // Consume bounty from escape reserve before transfers (reentrancy-safe posture).
        p.escape_stable -= bounty;

        uint256 initiatorCut = (bounty * g.recovery_config.bps_initiator) / 10_000;
        uint256 remainder = bounty - initiatorCut;

        // Initiator payout address resolved via ShellRegistry (shell_id is not an address).
        address initiatorPayout = _payoutOrRevert(a.initiator_shell_id);
        if (initiatorCut != 0) {
            IERC20(stable).safeTransfer(initiatorPayout, initiatorCut);
        }

        // Distribute remainder across RS members (live recovery set), excluding initiator, skipping duplicates.
        bytes32[] memory rs = g.recovery_config.recovery_set;
        uint256 n = 0;
        for (uint256 i = 0; i < rs.length; i++) {
            bytes32 sid = rs[i];
            if (sid == a.initiator_shell_id) continue;
            if (_seenBefore(rs, i, sid)) continue;
            n++;
        }

        if (n != 0 && remainder != 0) {
            uint256 perMember = remainder / n;
            if (perMember != 0) {
                for (uint256 i = 0; i < rs.length; i++) {
                    bytes32 sid = rs[i];
                    if (sid == a.initiator_shell_id) continue;
                    if (_seenBefore(rs, i, sid)) continue;
                    address payout = _payoutOrRevert(sid);
                    IERC20(stable).safeTransfer(payout, perMember);
                }
            }
            // Dust stays in-wallet (unreserved after escape_stable decrement).
        }
    }

    function exitRecovery(bytes32 ghost_id) external override {
        _onlyOwner(ghost_id);
        if (!_verifyTEC(ghost_id)) revert TECFailed(ghost_id);
        SESSION_MANAGER.exitRecovery(ghost_id);
    }

    // ─── Internal Helpers ──────────────────────────────────────────────────

    function _onlyOwner(bytes32 ghost_id) internal view {
        address owner = wallet_owner[ghost_id];
        if (owner == address(0) || owner != msg.sender) revert NotOwner(ghost_id, msg.sender);
    }

    function _currentEpoch() internal view returns (uint256) {
        uint256 genesis = IEpochClock(address(SESSION_MANAGER)).GENESIS_TIME();
        uint256 epochLen = IEpochClock(address(SESSION_MANAGER)).EPOCH_LEN();
        if (epochLen == 0) revert InvalidPolicy();
        if (block.timestamp < genesis) revert InvalidPolicy();
        return (block.timestamp - genesis) / epochLen;
    }

    function _requireAllowedOrRoaming(bytes32 ghost_id, bytes32 shell_id) internal view {
        Policy storage p = _policy[ghost_id];
        if (p.roaming_enabled) return;
        if (!isAllowedShell(ghost_id, shell_id)) revert ShellNotAllowed(ghost_id, shell_id);
    }

    function _enforceSpend(bytes32 ghost_id, uint256 amount) internal {
        Policy storage p = _policy[ghost_id];

        uint256 now_epoch = _currentEpoch();
        uint256 spentNow = (_spentEpoch[ghost_id] == now_epoch) ? _spent[ghost_id] : 0;

        uint256 newSpent = spentNow + amount;
        if (newSpent > p.hot_allowance) revert HotAllowanceExceeded(spentNow, amount, p.hot_allowance);

        // Escape reserves are sacred.
        if (address(this).balance < p.escape_gas) revert EscapeReserveViolation();

        GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
        address stable = g.recovery_config.bounty_asset;
        if (p.escape_stable != 0) {
            if (stable == address(0)) revert InvalidPolicy();
            uint256 bal = IERC20(stable).balanceOf(address(this));
            address spendAsset = _assetByGhost[ghost_id];
            if (spendAsset == stable) {
                if (bal < amount) revert EscapeReserveViolation();
                if (bal - amount < p.escape_stable) revert EscapeReserveViolation();
            } else {
                if (bal < p.escape_stable) revert EscapeReserveViolation();
            }
        }

        _spent[ghost_id] = newSpent;
        _spentEpoch[ghost_id] = now_epoch;
    }

    function _verifyTEC(bytes32 ghost_id) internal view returns (bool) {
        Policy storage p = _policy[ghost_id];
        SessionState memory s = SESSION_MANAGER.getSession(ghost_id);

        if (p.home_shell != bytes32(0) && s.shell_id == p.home_shell) return true;

        bytes32[] storage trusted = p.trusted_shells;
        for (uint256 i = 0; i < trusted.length; i++) {
            if (trusted[i] == s.shell_id) return true;
        }

        ShellRecord memory sh = SHELL_REGISTRY.getShell(s.shell_id);
        if (sh.assurance_tier == 3 && sh.certificate_id != bytes32(0)) return true;

        return false;
    }

    function _payoutOrRevert(bytes32 shell_id) internal view returns (address payout) {
        ShellRecord memory sh = SHELL_REGISTRY.getShell(shell_id);
        if (sh.shell_id != shell_id) revert NotFound(shell_id);
        payout = sh.payout_address;
        if (payout == address(0)) revert InvalidPolicy();
    }

    function _seenBefore(bytes32[] memory arr, uint256 idx, bytes32 val) internal pure returns (bool) {
        for (uint256 i = 0; i < idx; i++) {
            if (arr[i] == val) return true;
        }
        return false;
    }

    /// @dev Policy numeric fields must stay below int256.max so delta arithmetic never overflows.
    uint256 internal constant _MAX_POLICY_VALUE = uint256(type(int256).max);

    function _setPolicy(bytes32 ghost_id, Policy calldata pol) internal {
        if (pol.hot_allowance > _MAX_POLICY_VALUE) revert InvalidPolicy();
        if (pol.escape_gas > _MAX_POLICY_VALUE) revert InvalidPolicy();
        if (pol.escape_stable > _MAX_POLICY_VALUE) revert InvalidPolicy();

        Policy storage p = _policy[ghost_id];

        p.home_shell = pol.home_shell;
        p.hot_allowance = pol.hot_allowance;
        p.escape_gas = pol.escape_gas;
        p.escape_stable = pol.escape_stable;
        p.t_guardian = pol.t_guardian;
        p.roaming_enabled = pol.roaming_enabled;

        delete p.allowed_shells;
        for (uint256 i = 0; i < pol.allowed_shells.length; i++) {
            bytes32 sid = pol.allowed_shells[i];
            if (_containsBytes32(p.allowed_shells, sid)) revert DuplicateEntry();
            p.allowed_shells.push(sid);
        }

        delete p.trusted_shells;
        for (uint256 i = 0; i < pol.trusted_shells.length; i++) {
            bytes32 sid = pol.trusted_shells[i];
            if (!_containsBytes32(p.allowed_shells, sid)) revert InvalidPolicy();
            if (_containsBytes32(p.trusted_shells, sid)) revert DuplicateEntry();
            p.trusted_shells.push(sid);
        }

        if (p.home_shell != bytes32(0) && !_containsBytes32(p.allowed_shells, p.home_shell)) revert InvalidPolicy();

        delete p.guardians;
        for (uint256 i = 0; i < pol.guardians.length; i++) {
            if (_containsGuardianHash(p.guardians, keccak256(pol.guardians[i]))) revert DuplicateEntry();
            p.guardians.push(pol.guardians[i]);
        }

        _requireValidGuardianThreshold(uint256(p.guardians.length), p.t_guardian);
    }

    function _containsBytes32(bytes32[] storage arr, bytes32 val) internal view returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == val) return true;
        }
        return false;
    }

    function _containsGuardianHash(bytes[] storage arr, bytes32 h) internal view returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (keccak256(arr[i]) == h) return true;
        }
        return false;
    }

    function _removeBytes32(bytes32[] storage arr, bytes32 val) internal {
        uint256 len = arr.length;
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == val) {
                arr[i] = arr[len - 1];
                arr.pop();
                return;
            }
        }
        revert NotFound(val);
    }

    function _removeBytes32IfPresent(bytes32[] storage arr, bytes32 val) internal {
        uint256 len = arr.length;
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == val) {
                arr[i] = arr[len - 1];
                arr.pop();
                return;
            }
        }
    }

    // ─── Delta Classification / Application ────────────────────────────────

    function _classifyPolicyDeltaCalldata(bytes32 ghost_id, PolicyDelta calldata delta) internal view returns (ChangeKind) {
        Policy storage p = _policy[ghost_id];
        bool tighten = false;
        bool loosen = false;

        if (delta.add_allowed_shells.length != 0) loosen = true;
        if (delta.remove_allowed_shells.length != 0) tighten = true;
        if (delta.add_trusted_shells.length != 0) loosen = true;
        if (delta.remove_trusted_shells.length != 0) tighten = true;

        if (delta.hot_allowance_delta > 0) loosen = true;
        else if (delta.hot_allowance_delta < 0) tighten = true;

        if (delta.escape_gas_delta > 0) tighten = true;
        else if (delta.escape_gas_delta < 0) loosen = true;

        if (delta.escape_stable_delta > 0) tighten = true;
        else if (delta.escape_stable_delta < 0) loosen = true;

        if (delta.new_home_shell != bytes32(0) && delta.new_home_shell != p.home_shell) loosen = true;

        if (delta.new_guardians.length != 0) {
            (uint256 added, uint256 removed) = _guardianSetDeltaCalldata(p.guardians, delta.new_guardians);
            if (added != 0) tighten = true;
            if (removed != 0) loosen = true;
        }

        if (delta.new_t_guardian != 0 && delta.new_t_guardian != p.t_guardian) {
            if (delta.new_t_guardian > p.t_guardian) tighten = true;
            else loosen = true;
        }

        if (delta.roaming_config.length != 0) {
            bool newRoam = abi.decode(delta.roaming_config, (bool));
            if (newRoam != p.roaming_enabled) {
                if (newRoam) loosen = true;
                else tighten = true;
            }
        }

        if (tighten && loosen) return ChangeKind.MIXED;
        if (tighten) return ChangeKind.TIGHTENING;
        if (loosen) return ChangeKind.LOOSENING;
        return ChangeKind.NONE;
    }

    function _classifyPolicyDeltaMemory(bytes32 ghost_id, PolicyDelta memory delta) internal view returns (ChangeKind) {
        Policy storage p = _policy[ghost_id];
        bool tighten = false;
        bool loosen = false;

        if (delta.add_allowed_shells.length != 0) loosen = true;
        if (delta.remove_allowed_shells.length != 0) tighten = true;
        if (delta.add_trusted_shells.length != 0) loosen = true;
        if (delta.remove_trusted_shells.length != 0) tighten = true;

        if (delta.hot_allowance_delta > 0) loosen = true;
        else if (delta.hot_allowance_delta < 0) tighten = true;

        if (delta.escape_gas_delta > 0) tighten = true;
        else if (delta.escape_gas_delta < 0) loosen = true;

        if (delta.escape_stable_delta > 0) tighten = true;
        else if (delta.escape_stable_delta < 0) loosen = true;

        if (delta.new_home_shell != bytes32(0) && delta.new_home_shell != p.home_shell) loosen = true;

        if (delta.new_guardians.length != 0) {
            (uint256 added, uint256 removed) = _guardianSetDeltaMemory(p.guardians, delta.new_guardians);
            if (added != 0) tighten = true;
            if (removed != 0) loosen = true;
        }

        if (delta.new_t_guardian != 0 && delta.new_t_guardian != p.t_guardian) {
            if (delta.new_t_guardian > p.t_guardian) tighten = true;
            else loosen = true;
        }

        if (delta.roaming_config.length != 0) {
            bool newRoam = abi.decode(delta.roaming_config, (bool));
            if (newRoam != p.roaming_enabled) {
                if (newRoam) loosen = true;
                else tighten = true;
            }
        }

        if (tighten && loosen) return ChangeKind.MIXED;
        if (tighten) return ChangeKind.TIGHTENING;
        if (loosen) return ChangeKind.LOOSENING;
        return ChangeKind.NONE;
    }

    function _applyPolicyDelta(bytes32 ghost_id, PolicyDelta memory d) internal {
        Policy storage p = _policy[ghost_id];

        // Allowed / Trusted Shells
        for (uint256 i = 0; i < d.remove_allowed_shells.length; i++) {
            bytes32 sid = d.remove_allowed_shells[i];
            if (sid == p.home_shell && p.home_shell != bytes32(0)) revert InvalidPolicy();
            _removeBytes32(p.allowed_shells, sid);
            _removeBytes32IfPresent(p.trusted_shells, sid);
        }

        for (uint256 i = 0; i < d.remove_trusted_shells.length; i++) {
            _removeBytes32(p.trusted_shells, d.remove_trusted_shells[i]);
        }

        for (uint256 i = 0; i < d.add_allowed_shells.length; i++) {
            bytes32 sid = d.add_allowed_shells[i];
            if (_containsBytes32(p.allowed_shells, sid)) revert DuplicateEntry();
            p.allowed_shells.push(sid);
        }

        for (uint256 i = 0; i < d.add_trusted_shells.length; i++) {
            bytes32 sid = d.add_trusted_shells[i];
            if (!_containsBytes32(p.allowed_shells, sid)) revert InvalidPolicy();
            if (_containsBytes32(p.trusted_shells, sid)) revert DuplicateEntry();
            p.trusted_shells.push(sid);
        }

        // Home shell (loosening)
        if (d.new_home_shell != bytes32(0)) {
            p.home_shell = d.new_home_shell;
        }

        // Spend limits / reserves
        if (d.hot_allowance_delta != 0) {
            int256 next = int256(p.hot_allowance) + d.hot_allowance_delta;
            if (next < 0) revert InvalidPolicy();
            p.hot_allowance = uint256(next);
        }
        if (d.escape_gas_delta != 0) {
            int256 next = int256(p.escape_gas) + d.escape_gas_delta;
            if (next < 0) revert InvalidPolicy();
            p.escape_gas = uint256(next);
        }
        if (d.escape_stable_delta != 0) {
            int256 next = int256(p.escape_stable) + d.escape_stable_delta;
            if (next < 0) revert InvalidPolicy();
            p.escape_stable = uint256(next);

            // escape_stable MUST include B_rescue_total.
            GhostRecord memory g = GHOST_REGISTRY.getGhost(ghost_id);
            if (p.escape_stable < g.recovery_config.bounty_total) revert InvalidPolicy();
        }

        // Guardians replacement (bytes[] comparisons are O(n*m); guardian sets are expected small in v1).
        if (d.new_guardians.length != 0) {
            delete p.guardians;
            for (uint256 i = 0; i < d.new_guardians.length; i++) {
                if (_containsGuardianHash(p.guardians, keccak256(d.new_guardians[i]))) revert DuplicateEntry();
                p.guardians.push(d.new_guardians[i]);
            }
        }

        if (d.new_t_guardian != 0) {
            p.t_guardian = d.new_t_guardian;
        }

        _requireValidGuardianThreshold(uint256(p.guardians.length), p.t_guardian);

        // Roaming toggle
        if (d.roaming_config.length != 0) {
            bool newRoam = abi.decode(d.roaming_config, (bool));
            p.roaming_enabled = newRoam;
        }

        if (p.home_shell != bytes32(0) && !_containsBytes32(p.allowed_shells, p.home_shell)) revert InvalidPolicy();
        for (uint256 i = 0; i < p.trusted_shells.length; i++) {
            if (!_containsBytes32(p.allowed_shells, p.trusted_shells[i])) revert InvalidPolicy();
        }

        // Emit if guardians were touched via delta.
        if (d.new_guardians.length != 0 || d.new_t_guardian != 0) {
            emit GuardiansUpdated(ghost_id, p.t_guardian);
        }
    }

    // ─── Guardians Helpers ────────────────────────────────────────────────

    function _classifyGuardiansChangeMemory(bytes32 ghost_id, bytes[] memory guardians, uint64 t_guardian) internal view returns (ChangeKind) {
        Policy storage p = _policy[ghost_id];

        bool tighten = false;
        bool loosen = false;

        (uint256 added, uint256 removed) = _guardianSetDeltaMemory(p.guardians, guardians);
        if (added != 0) tighten = true;
        if (removed != 0) loosen = true;

        if (t_guardian != p.t_guardian) {
            if (t_guardian > p.t_guardian) tighten = true;
            else loosen = true;
        }

        if (tighten && loosen) return ChangeKind.MIXED;
        if (tighten) return ChangeKind.TIGHTENING;
        if (loosen) return ChangeKind.LOOSENING;
        return ChangeKind.NONE;
    }

    function _classifyGuardiansChangeCalldata(bytes32 ghost_id, bytes[] calldata guardians, uint64 t_guardian) internal view returns (ChangeKind) {
        Policy storage p = _policy[ghost_id];

        bool tighten = false;
        bool loosen = false;

        (uint256 added, uint256 removed) = _guardianSetDeltaCalldata(p.guardians, guardians);
        if (added != 0) tighten = true;
        if (removed != 0) loosen = true;

        if (t_guardian != p.t_guardian) {
            if (t_guardian > p.t_guardian) tighten = true;
            else loosen = true;
        }

        if (tighten && loosen) return ChangeKind.MIXED;
        if (tighten) return ChangeKind.TIGHTENING;
        if (loosen) return ChangeKind.LOOSENING;
        return ChangeKind.NONE;
    }

    function _applyGuardians(bytes32 ghost_id, bytes[] memory guardians, uint64 t_guardian) internal {
        Policy storage p = _policy[ghost_id];
        delete p.guardians;
        for (uint256 i = 0; i < guardians.length; i++) {
            if (_containsGuardianHash(p.guardians, keccak256(guardians[i]))) revert DuplicateEntry();
            p.guardians.push(guardians[i]);
        }
        p.t_guardian = t_guardian;
        _requireValidGuardianThreshold(uint256(p.guardians.length), p.t_guardian);
        emit GuardiansUpdated(ghost_id, p.t_guardian);
    }

    function _requireValidGuardianThreshold(uint256 n, uint64 t_guardian) internal pure {
        if (n == 0) {
            if (t_guardian != 0) revert InvalidPolicy();
            return;
        }
        if (t_guardian == 0 || uint256(t_guardian) > n) revert InvalidPolicy();
    }

    function _guardianSetDeltaCalldata(bytes[] storage oldSet, bytes[] calldata newSet) internal view returns (uint256 added, uint256 removed) {
        // O(n*m) set comparison; guardian sets are expected small in v1.
        for (uint256 i = 0; i < oldSet.length; i++) {
            bytes32 h = keccak256(oldSet[i]);
            bool found = false;
            for (uint256 j = 0; j < newSet.length; j++) {
                if (keccak256(newSet[j]) == h) {
                    found = true;
                    break;
                }
            }
            if (!found) removed++;
        }

        for (uint256 i = 0; i < newSet.length; i++) {
            bytes32 h = keccak256(newSet[i]);
            bool found = false;
            for (uint256 j = 0; j < oldSet.length; j++) {
                if (keccak256(oldSet[j]) == h) {
                    found = true;
                    break;
                }
            }
            if (!found) added++;
        }
    }

    function _guardianSetDeltaMemory(bytes[] storage oldSet, bytes[] memory newSet) internal view returns (uint256 added, uint256 removed) {
        // O(n*m) set comparison; guardian sets are expected small in v1.
        for (uint256 i = 0; i < oldSet.length; i++) {
            bytes32 h = keccak256(oldSet[i]);
            bool found = false;
            for (uint256 j = 0; j < newSet.length; j++) {
                if (keccak256(newSet[j]) == h) {
                    found = true;
                    break;
                }
            }
            if (!found) removed++;
        }

        for (uint256 i = 0; i < newSet.length; i++) {
            bytes32 h = keccak256(newSet[i]);
            bool found = false;
            for (uint256 j = 0; j < oldSet.length; j++) {
                if (keccak256(oldSet[j]) == h) {
                    found = true;
                    break;
                }
            }
            if (!found) added++;
        }
    }
}
