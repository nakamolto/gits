// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {GhostWallet} from "src/GhostWallet.sol";
import {SessionManager} from "src/SessionManager.sol";

import {
    Policy,
    PolicyDelta,
    SessionParams,
    SessionState,
    SessionMode,
    StrandedReason,
    BondStatus,
    RecoveryAttempt,
    GhostRecord,
    ShellRecord,
    RecoveryConfig
} from "src/types/GITSTypes.sol";

import {IGhostRegistry} from "src/interfaces/IGhostRegistry.sol";
import {IShellRegistry} from "src/interfaces/IShellRegistry.sol";
import {IVerifierRegistry} from "src/interfaces/IVerifierRegistry.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract GhostRegistryMock is IGhostRegistry {
    mapping(bytes32 => GhostRecord) internal _ghosts;
    mapping(bytes32 => bool) internal _passportEligible;

    error GhostAlreadyRegistered(bytes32 ghost_id);
    error GhostNotRegistered(bytes32 ghost_id);
    error Unauthorized();

    function setPassportEligible(bytes32 ghost_id, bool eligible) external {
        _passportEligible[ghost_id] = eligible;
    }

    function setGhost(bytes32 ghost_id, GhostRecord calldata g) external {
        _ghosts[ghost_id] = g;
    }

    // ─── IGhostRegistry ────────────────────────────────────────────────────

    function registerGhost(
        bytes32 ghost_id,
        bytes calldata identity_pubkey,
        address wallet,
        bytes32,
        RecoveryConfig calldata recoveryConfig
    ) external {
        if (msg.sender != wallet) revert Unauthorized();
        if (wallet == address(0)) revert Unauthorized();
        if (_ghosts[ghost_id].wallet != address(0)) revert GhostAlreadyRegistered(ghost_id);

        GhostRecord storage g = _ghosts[ghost_id];
        g.ghost_id = ghost_id;
        g.identity_pubkey = identity_pubkey;
        g.wallet = wallet;
        g.recovery_config = recoveryConfig;
    }

    function bondGhost(bytes32, address, uint256) external pure {
        revert("not implemented");
    }

    function beginUnbondGhost(bytes32, uint256) external pure {
        revert("not implemented");
    }

    function finalizeUnbondGhost(bytes32) external pure {
        revert("not implemented");
    }

    function ghostPassportEligible(bytes32 ghost_id, uint256) external view returns (bool) {
        return _passportEligible[ghost_id];
    }

    function rotateSigner(bytes32, bytes calldata, bytes calldata) external pure {
        revert("not implemented");
    }

    function publishCheckpoint(bytes32, uint256, bytes32, bytes32, bytes calldata, bytes calldata) external pure {
        revert("not implemented");
    }

    function setRecoveryConfig(bytes32, RecoveryConfig calldata) external pure {
        revert("not implemented");
    }

    function recordRewardCredit(bytes32, uint256) external pure {
        revert("not implemented");
    }

    function cumulativeRewards(bytes32) external pure returns (uint256) {
        revert("not implemented");
    }

    function getGhost(bytes32 ghost_id) external view returns (GhostRecord memory) {
        GhostRecord memory g = _ghosts[ghost_id];
        if (g.wallet == address(0)) revert GhostNotRegistered(ghost_id);
        return g;
    }
}

contract ShellRegistryMock is IShellRegistry {
    mapping(bytes32 => ShellRecord) internal _shells;

    function setShell(bytes32 shell_id, ShellRecord calldata s) external {
        _shells[shell_id] = s;
    }

    // ─── IShellRegistry (only functions used by SessionManager/GhostWallet are meaningful) ───

    function registerShell(
        bytes32,
        bytes calldata,
        bytes calldata,
        address,
        bytes32,
        address,
        uint256,
        bytes calldata,
        bytes[] calldata,
        bytes calldata
    ) external pure {
        revert("not implemented");
    }

    function proposeIdentityKeyUpdate(bytes32, bytes calldata, bytes calldata) external pure {
        revert("not implemented");
    }

    function confirmIdentityKeyUpdate(bytes32) external pure {
        revert("not implemented");
    }

    function proposeOfferSignerUpdate(bytes32, bytes calldata) external pure {
        revert("not implemented");
    }

    function confirmOfferSignerUpdate(bytes32) external pure {
        revert("not implemented");
    }

    function proposeRecoveryKeyUpdate(bytes32, bytes calldata) external pure {
        revert("not implemented");
    }

    function confirmRecoveryKeyUpdate(bytes32) external pure {
        revert("not implemented");
    }

    function updateCapabilityHash(bytes32, bytes32) external pure {
        revert("not implemented");
    }

    function setPayoutAddress(bytes32, address) external pure {
        revert("not implemented");
    }

    function setCertificate(bytes32, bytes calldata, bytes[] calldata) external pure {
        revert("not implemented");
    }

    function revokeCertificate(bytes32) external pure {
        revert("not implemented");
    }

    function beginUnbond(bytes32, uint256) external pure {
        revert("not implemented");
    }

    function finalizeUnbond(bytes32) external pure {
        revert("not implemented");
    }

    function bondSafeHaven(bytes32, uint256) external pure {
        revert("not implemented");
    }

    function beginUnbondSafeHaven(bytes32) external pure {
        revert("not implemented");
    }

    function finalizeUnbondSafeHaven(bytes32) external pure {
        revert("not implemented");
    }

    function slashShell(bytes32, uint256, bytes32) external pure {
        revert("not implemented");
    }

    function slashSafeHaven(bytes32, uint256, address) external pure {
        revert("not implemented");
    }

    function getShell(bytes32 shell_id) external view returns (ShellRecord memory) {
        return _shells[shell_id];
    }

    function assuranceTier(bytes32 shell_id) external view returns (uint8) {
        return _shells[shell_id].assurance_tier;
    }
}

contract VerifierRegistryMock is IVerifierRegistry {
    mapping(address => bool) internal _active;
    mapping(bytes32 => bool) internal _measurementAllowed;

    function setActiveVerifier(address v, bool active) external {
        _active[v] = active;
    }

    function setMeasurementAllowed(bytes32 measurement_hash, bool allowed) external {
        _measurementAllowed[measurement_hash] = allowed;
    }

    // ─── IVerifierRegistry ─────────────────────────────────────────────────

    function registerVerifier(address, uint256) external pure {
        revert("not implemented");
    }

    function increaseStake(address, uint256) external pure {
        revert("not implemented");
    }

    function beginDecreaseStake(address, uint256) external pure {
        revert("not implemented");
    }

    function withdrawDecreasedStake(address) external pure {
        revert("not implemented");
    }

    function slashVerifier(address, address, uint256, bytes32) external pure {
        revert("not implemented");
    }

    function proveVerifierEquivocation(address, bytes32, bytes calldata, bytes calldata, bytes calldata, bytes calldata) external pure {
        revert("not implemented");
    }

    function allowMeasurement(bytes32, uint8, uint64, bytes[] calldata) external pure {
        revert("not implemented");
    }

    function revokeMeasurement(bytes32, uint64, bytes[] calldata) external pure {
        revert("not implemented");
    }

    function isActiveVerifier(address verifier) external view returns (bool) {
        return _active[verifier];
    }

    function stakeScore(address) external pure returns (uint256) {
        return 0;
    }

    function activeStake(address, address) external pure returns (uint256) {
        return 0;
    }

    function isMeasurementAllowed(bytes32 measurement_hash, uint8) external view returns (bool) {
        return _measurementAllowed[measurement_hash];
    }
}

contract SessionManagerExitMock {
    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    SessionState internal _session;
    bool public exitCalled;

    constructor(uint256 genesisTime_, uint256 epochLen_) {
        GENESIS_TIME = genesisTime_;
        EPOCH_LEN = epochLen_;
    }

    function setSession(SessionState calldata s) external {
        _session = s;
    }

    function getSession(bytes32) external view returns (SessionState memory) {
        return _session;
    }

    function exitRecovery(bytes32) external {
        exitCalled = true;
    }
}

contract GhostWalletTest is Test {
    event PolicyChangeProposed(bytes32 indexed ghost_id, bytes32 proposal_id, uint256 executable_at);
    event PolicyChangeExecuted(bytes32 indexed ghost_id, bytes32 proposal_id);
    event GuardiansUpdated(bytes32 indexed ghost_id, uint64 t_guardian);

    uint256 internal constant GENESIS_TIME = 1_000_000;
    uint256 internal constant EPOCH_LEN = 10;

    uint256 internal constant LEASE_DEFAULT = 5;
    uint256 internal constant T_TRUST_REFRESH = 100;

    uint256 internal constant T_RECOVERY_TIMEOUT = 4;
    uint256 internal constant T_RECOVERY_TAKEOVER = 2;
    uint256 internal constant T_RECOVERY_COOLDOWN = 3;

    uint256 internal constant B_START = 1 ether;

    uint8 internal constant B_PASSPORT_FILTERS = 3;
    uint256 internal constant C_PASSPORT = 12;
    uint256 internal constant BLOOM_M_BITS = 256;
    uint8 internal constant BLOOM_K_HASHES = 3;

    uint256 internal constant T_MIGRATION_TIMEOUT = 5;
    uint64 internal constant K_VERIFIER_THRESHOLD = 2;

    uint256 internal constant T_POLICY_TIMELOCK = 2;

    GhostRegistryMock internal ghostRegistry;
    ShellRegistryMock internal shellRegistry;
    VerifierRegistryMock internal verifierRegistry;

    SessionManager internal sm;
    GhostWallet internal wallet;

    ERC20Mock internal stable;

    address internal receiptManager = address(0xBEEF);
    address internal owner = makeAddr("owner");

    bytes32 internal ghostId = keccak256("ghost-1");
    bytes32 internal salt = bytes32(uint256(0xCAFE));

    bytes32 internal homeShell = keccak256("home-shell");
    bytes32 internal allowedShell = keccak256("allowed-shell");
    bytes32 internal at3Shell = keccak256("at3-shell");

    function setUp() public {
        stable = new ERC20Mock("Stable", "STBL");

        ghostRegistry = new GhostRegistryMock();
        shellRegistry = new ShellRegistryMock();
        verifierRegistry = new VerifierRegistryMock();

        SessionManager.InitParams memory p = SessionManager.InitParams({
            genesis_time: GENESIS_TIME,
            epoch_len: EPOCH_LEN,
            lease_default: LEASE_DEFAULT,
            t_trust_refresh: T_TRUST_REFRESH,
            t_recovery_timeout: T_RECOVERY_TIMEOUT,
            t_recovery_takeover: T_RECOVERY_TAKEOVER,
            t_recovery_cooldown: T_RECOVERY_COOLDOWN,
            b_start: B_START,
            passport_filters: B_PASSPORT_FILTERS,
            c_passport: C_PASSPORT,
            bloom_m_bits: BLOOM_M_BITS,
            bloom_k_hashes: BLOOM_K_HASHES,
            t_migration_timeout: T_MIGRATION_TIMEOUT,
            k_verifier_threshold: K_VERIFIER_THRESHOLD,
            ghost_registry: address(ghostRegistry),
            shell_registry: address(shellRegistry),
            receipt_manager: receiptManager,
            verifier_registry: address(verifierRegistry)
        });

        sm = new SessionManager(p);
        wallet = new GhostWallet(address(sm), address(shellRegistry), address(ghostRegistry), T_POLICY_TIMELOCK);

        ghostRegistry.setPassportEligible(ghostId, true);

        // Shell records used for sessions/TEC. Minimal bonded shells.
        _setBondedShell(homeShell, 2, bytes32(0));
        _setBondedShell(allowedShell, 2, bytes32(0));
        _setBondedShell(at3Shell, 3, bytes32(uint256(1))); // AT3 + cert for TEC

        vm.warp(GENESIS_TIME + 1);

        _registerDefaultGhost();

        // Ensure wallet has gas reserve budget by default.
        vm.deal(address(wallet), 10 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    function _setBondedShell(bytes32 shell_id, uint8 at, bytes32 certId) internal {
        ShellRecord memory s;
        s.shell_id = shell_id;
        s.bond_status = uint8(BondStatus.BONDED);
        s.assurance_tier = at;
        s.certificate_id = certId;
        s.payout_address = address(uint160(uint256(keccak256(abi.encodePacked("payout", shell_id)))));
        shellRegistry.setShell(shell_id, s);
    }

    function _sessionParams(address asset) internal pure returns (SessionParams memory sp) {
        sp = SessionParams({
            price_per_SU: 1,
            max_SU: 1,
            lease_expiry_epoch: 0,
            tenure_limit_epochs: 10,
            ghost_session_key: "",
            shell_session_key: "",
            submitter_address: address(0x1234),
            asset: asset
        });
    }

    function _registerDefaultGhost() internal {
        bytes32[] memory rs = new bytes32[](1);
        rs[0] = bytes32(uint256(0xA));

        RecoveryConfig memory rc = RecoveryConfig({
            recovery_set: rs,
            threshold: 1,
            bounty_asset: address(stable),
            bounty_total: 100,
            bps_initiator: 1000
        });

        bytes32[] memory allowed = new bytes32[](3);
        allowed[0] = homeShell;
        allowed[1] = allowedShell;
        allowed[2] = at3Shell;

        bytes32[] memory trusted = new bytes32[](1);
        trusted[0] = allowedShell;

        Policy memory pol = Policy({
            home_shell: homeShell,
            allowed_shells: allowed,
            trusted_shells: trusted,
            hot_allowance: 1_000 ether,
            escape_gas: 1 ether,
            escape_stable: 1_000 ether,
            guardians: new bytes[](0),
            t_guardian: 0,
            roaming_enabled: false
        });

        vm.prank(owner);
        wallet.registerGhost(ghostId, hex"01", salt, rc, pol);
    }

    function _warpToEpoch(uint256 epoch) internal {
        vm.warp(GENESIS_TIME + epoch * EPOCH_LEN + 1);
    }

    function _openHomeSession() internal {
        vm.prank(owner);
        wallet.openSession(ghostId, homeShell, _sessionParams(address(stable)));
    }

    function _findProposed(bytes32 ghost_id) internal returns (bytes32 proposalId, uint256 executableAt) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("PolicyChangeProposed(bytes32,bytes32,uint256)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(wallet)) continue;
            if (logs[i].topics.length < 2) continue;
            if (logs[i].topics[0] != sig) continue;
            if (bytes32(logs[i].topics[1]) != ghost_id) continue;
            (proposalId, executableAt) = abi.decode(logs[i].data, (bytes32, uint256));
            return (proposalId, executableAt);
        }
        revert("proposal not found");
    }

    // ─── Policy Views ───────────────────────────────────────────────────────

    function test_policyViews_basic() public {
        Policy memory p = wallet.getPolicy(ghostId);
        assertEq(p.home_shell, homeShell);
        assertEq(wallet.homeShell(ghostId), homeShell);
        assertTrue(wallet.isAllowedShell(ghostId, homeShell));
        assertFalse(wallet.isAllowedShell(ghostId, bytes32(uint256(0xDEAD))));
        (uint256 eg, uint256 es) = wallet.escapeReserve(ghostId);
        assertEq(eg, 1 ether);
        assertEq(es, 1_000 ether);
        assertEq(wallet.hotAllowance(ghostId), 1_000 ether);
        assertEq(wallet.spentThisEpoch(ghostId), 0);
    }

    // ─── Tightening ─────────────────────────────────────────────────────────

    function test_tightening_removeTrustedShell_immediate() public {
        Policy memory p0 = wallet.getPolicy(ghostId);
        assertEq(p0.trusted_shells.length, 1);

        vm.prank(owner);
        wallet.removeTrustedShell(ghostId, allowedShell);

        Policy memory p1 = wallet.getPolicy(ghostId);
        assertEq(p1.trusted_shells.length, 0);
    }

    function test_tightening_removeAllowedShell_cascadesTrusted() public {
        // allowedShell starts as both allowed and trusted (see _registerDefaultGhost).
        assertTrue(wallet.isAllowedShell(ghostId, allowedShell));
        assertTrue(_isTrusted(ghostId, allowedShell));

        vm.prank(owner);
        wallet.removeAllowedShell(ghostId, allowedShell);

        assertFalse(wallet.isAllowedShell(ghostId, allowedShell));
        assertFalse(_isTrusted(ghostId, allowedShell));
    }

    function test_tightening_decreaseHotAllowance_immediate() public {
        PolicyDelta memory d;
        d.hot_allowance_delta = -100 ether;

        bytes32 expectedPid = keccak256(abi.encode(ghostId, d, block.timestamp, uint256(0)));

        vm.expectEmit(true, false, false, true, address(wallet));
        emit PolicyChangeExecuted(ghostId, expectedPid);

        vm.prank(owner);
        bytes32 pid = wallet.proposePolicyChange(ghostId, d);
        assertEq(pid, expectedPid);
        assertEq(wallet.hotAllowance(ghostId), 900 ether);
    }

    // ─── Loosening + Timelock + TEC ─────────────────────────────────────────

    function test_loosening_increaseHotAllowance_timelocked_requiresTEC() public {
        _openHomeSession();

        PolicyDelta memory d;
        d.hot_allowance_delta = 100 ether;

        vm.prank(owner);
        bytes32 pid = wallet.proposePolicyChange(ghostId, d);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.TimelockNotElapsed.selector, uint256(0), uint256(T_POLICY_TIMELOCK)));
        wallet.executePolicyChange(ghostId, pid);

        _warpToEpoch(T_POLICY_TIMELOCK);
        vm.prank(owner);
        wallet.executePolicyChange(ghostId, pid);

        assertEq(wallet.hotAllowance(ghostId), 1_100 ether);
    }

    function test_loosening_execute_revertsOnTECFails() public {
        // Open session on a non-home, non-trusted, non-AT3+cert shell.
        bytes32 badShell = keccak256("bad-shell");
        _setBondedShell(badShell, 2, bytes32(0));

        // Allow it for session open.
        PolicyDelta memory allowDelta;
        bytes32[] memory addAllowed = new bytes32[](1);
        addAllowed[0] = badShell;
        allowDelta.add_allowed_shells = addAllowed;

        _openHomeSession();
        vm.prank(owner);
        bytes32 pidAllow = wallet.proposePolicyChange(ghostId, allowDelta);
        _warpToEpoch(T_POLICY_TIMELOCK);
        vm.prank(owner);
        wallet.executePolicyChange(ghostId, pidAllow);

        // Close current session and reopen on badShell (SessionManager only allows a new session when stranded).
        vm.prank(owner);
        wallet.closeSession(ghostId);

        vm.prank(owner);
        wallet.openSession(ghostId, badShell, _sessionParams(address(stable)));

        PolicyDelta memory d;
        d.hot_allowance_delta = 1;
        vm.prank(owner);
        bytes32 pid = wallet.proposePolicyChange(ghostId, d);

        _warpToEpoch(T_POLICY_TIMELOCK * 2);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.TECFailed.selector, ghostId));
        wallet.executePolicyChange(ghostId, pid);
    }

    function test_loosening_execute_succeedsOnAT3WithCert() public {
        // Open session on AT3+cert shell (not home or trusted).
        PolicyDelta memory d;
        d.hot_allowance_delta = 100 ether;

        vm.prank(owner);
        wallet.openSession(ghostId, at3Shell, _sessionParams(address(stable)));

        vm.prank(owner);
        bytes32 pid = wallet.proposePolicyChange(ghostId, d);

        _warpToEpoch(T_POLICY_TIMELOCK);
        vm.prank(owner);
        wallet.executePolicyChange(ghostId, pid);

        assertEq(wallet.hotAllowance(ghostId), 1_100 ether);
    }

    // ─── Mixed Delta Rejection ──────────────────────────────────────────────

    function test_mixedDeltaRejected() public {
        PolicyDelta memory d;
        bytes32[] memory addAllowed = new bytes32[](1);
        addAllowed[0] = keccak256("new-shell");
        d.add_allowed_shells = addAllowed; // loosening
        d.hot_allowance_delta = -1; // tightening

        vm.prank(owner);
        vm.expectRevert(GhostWallet.MixedDelta.selector);
        wallet.proposePolicyChange(ghostId, d);
    }

    // ─── Spending Enforcement ───────────────────────────────────────────────

    function test_spending_hotAllowanceAndEscapeReserve() public {
        _openHomeSession();

        // Mint just enough so a second small spend would dip below escape_stable.
        stable.mint(address(wallet), 1_400 ether);

        vm.prank(owner);
        wallet.fundNextEpoch(ghostId, 400 ether);
        assertEq(wallet.spentThisEpoch(ghostId), 400 ether);
        assertEq(stable.balanceOf(address(sm)), 400 ether);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.HotAllowanceExceeded.selector, uint256(400 ether), uint256(700 ether), uint256(1_000 ether)));
        wallet.fundNextEpoch(ghostId, 700 ether); // would exceed 1_000 total

        vm.prank(owner);
        vm.expectRevert(GhostWallet.EscapeReserveViolation.selector);
        wallet.fundNextEpoch(ghostId, 1 ether); // would drop below escape_stable (1_000 ether)
    }

    function test_spentThisEpoch_resetsEachEpoch() public {
        _openHomeSession();
        stable.mint(address(wallet), 2_000 ether);

        vm.prank(owner);
        wallet.fundNextEpoch(ghostId, 100 ether);
        assertEq(wallet.spentThisEpoch(ghostId), 100 ether);

        _warpToEpoch(1);
        assertEq(wallet.spentThisEpoch(ghostId), 0);

        vm.prank(owner);
        wallet.fundNextEpoch(ghostId, 50 ether);
        assertEq(wallet.spentThisEpoch(ghostId), 50 ether);
    }

    // ─── Delegation / SessionManager Integration ────────────────────────────

    function test_delegation_openRenewClose() public {
        vm.prank(owner);
        wallet.openSession(ghostId, homeShell, _sessionParams(address(stable)));

        SessionState memory s0 = sm.getSession(ghostId);
        uint256 oldExpiry = s0.lease_expiry_epoch;

        _warpToEpoch(1);
        vm.prank(owner);
        wallet.renewLease(ghostId);

        SessionState memory s1 = sm.getSession(ghostId);
        assertTrue(s1.lease_expiry_epoch > oldExpiry);

        vm.prank(owner);
        wallet.closeSession(ghostId);

        SessionState memory s2 = sm.getSession(ghostId);
        assertEq(s2.mode, uint8(SessionMode.STRANDED));
        assertEq(s2.stranded_reason, uint8(StrandedReason.VOLUNTARY_CLOSE));
    }

    function test_delegation_migrationFlow() public {
        _openHomeSession();

        // Ensure destination is allowed.
        assertTrue(wallet.isAllowedShell(ghostId, allowedShell));

        bytes memory proof = "proof";
        bytes32 bundleHash = keccak256(proof);
        vm.prank(owner);
        wallet.startMigration(ghostId, allowedShell, bundleHash);

        SessionState memory parent = sm.getSession(ghostId);
        assertTrue(parent.pending_migration);
        assertEq(parent.mig_dest_shell_id, allowedShell);

        // Open staging session to destination shell.
        vm.prank(owner);
        wallet.openSession(ghostId, allowedShell, _sessionParams(address(stable)));

        SessionState memory afterStaging = sm.getSession(ghostId);
        assertTrue(afterStaging.pending_migration);
        assertTrue(afterStaging.mig_dest_session_id != 0);

        vm.prank(owner);
        wallet.finalizeMigration(ghostId, allowedShell, proof);

        SessionState memory s = sm.getSession(ghostId);
        assertEq(s.shell_id, allowedShell);
        assertFalse(s.staging);
        assertFalse(s.pending_migration);
    }

    // ─── Guardians ──────────────────────────────────────────────────────────

    function test_guardians_addImmediate_removeTimelocked() public {
        bytes[] memory g2 = new bytes[](2);
        g2[0] = abi.encodePacked(bytes32(uint256(1)));
        g2[1] = abi.encodePacked(bytes32(uint256(2)));

        vm.expectEmit(true, false, false, true, address(wallet));
        emit GuardiansUpdated(ghostId, 2);

        vm.prank(owner);
        wallet.setGuardians(ghostId, g2, 2);

        Policy memory p1 = wallet.getPolicy(ghostId);
        assertEq(p1.guardians.length, 2);
        assertEq(p1.t_guardian, 2);

        // Propose loosening: remove one guardian and lower threshold.
        bytes[] memory g1 = new bytes[](1);
        g1[0] = g2[0];

        _openHomeSession();

        vm.recordLogs();
        vm.prank(owner);
        wallet.setGuardians(ghostId, g1, 1);

        (bytes32 pid, uint256 execAt) = _findProposed(ghostId);
        assertEq(execAt, T_POLICY_TIMELOCK);

        _warpToEpoch(T_POLICY_TIMELOCK);
        vm.prank(owner);
        wallet.executePolicyChange(ghostId, pid);

        Policy memory p2 = wallet.getPolicy(ghostId);
        assertEq(p2.guardians.length, 1);
        assertEq(p2.t_guardian, 1);
    }

    function test_guardians_mixedReplacementRejected() public {
        bytes[] memory g1 = new bytes[](1);
        g1[0] = abi.encodePacked(bytes32(uint256(1)));

        vm.prank(owner);
        wallet.setGuardians(ghostId, g1, 1);

        bytes[] memory g1Different = new bytes[](1);
        g1Different[0] = abi.encodePacked(bytes32(uint256(2))); // remove old, add new => mixed

        vm.prank(owner);
        vm.expectRevert(GhostWallet.MixedDelta.selector);
        wallet.setGuardians(ghostId, g1Different, 1);
    }

    // ─── Recovery ──────────────────────────────────────────────────────────

    function test_recovery_payRescueBounty_onlySessionManager_paysPayoutAddresses() public {
        // Setup a ghost with a 3-member recovery set and bounty_total=1000.
        bytes32 gid = keccak256("ghost-recovery");

        address sh1 = makeAddr("sh1");
        address sh2 = makeAddr("sh2");
        address sh3 = makeAddr("sh3");
        vm.deal(sh1, 10 ether);
        vm.deal(sh2, 10 ether);
        vm.deal(sh3, 10 ether);

        bytes32 sh1Id = bytes32(uint256(uint160(sh1)));
        bytes32 sh2Id = bytes32(uint256(uint160(sh2)));
        bytes32 sh3Id = bytes32(uint256(uint160(sh3)));

        bytes32[] memory rs = new bytes32[](3);
        rs[0] = sh1Id;
        rs[1] = sh2Id;
        rs[2] = sh3Id;

        RecoveryConfig memory rc = RecoveryConfig({
            recovery_set: rs,
            threshold: 2,
            bounty_asset: address(stable),
            bounty_total: 1_000,
            bps_initiator: 1_000 // 10%
        });

        bytes32[] memory allowed = new bytes32[](1);
        allowed[0] = homeShell;

        Policy memory pol = Policy({
            home_shell: homeShell,
            allowed_shells: allowed,
            trusted_shells: new bytes32[](0),
            hot_allowance: 0,
            escape_gas: 0,
            escape_stable: 2_000,
            guardians: new bytes[](0),
            t_guardian: 0,
            roaming_enabled: false
        });

        vm.prank(owner);
        wallet.registerGhost(gid, hex"01", salt, rc, pol);
        ghostRegistry.setPassportEligible(gid, true);

        // Register recovery set shells with payout addresses and safe-haven requirements.
        _setSafeHavenShell(sh1Id, makeAddr("p1"));
        _setSafeHavenShell(sh2Id, makeAddr("p2"));
        _setSafeHavenShell(sh3Id, makeAddr("p3"));

        // Open a session so startRecovery can run.
        vm.prank(owner);
        wallet.openSession(gid, homeShell, _sessionParams(address(stable)));

        // Create recovery attempt in SessionManager (attempt_id=1).
        vm.prank(sh1);
        uint64 attemptId = sm.startRecovery{value: B_START}(gid);
        assertEq(attemptId, 1);

        stable.mint(address(wallet), 10_000);

        // Non-SessionManager caller must revert.
        vm.expectRevert(GhostWallet.OnlySessionManager.selector);
        wallet.payRescueBounty(gid, attemptId);

        // Pay bounty as SessionManager.
        address p1 = shellRegistry.getShell(sh1Id).payout_address;
        address p2 = shellRegistry.getShell(sh2Id).payout_address;
        address p3 = shellRegistry.getShell(sh3Id).payout_address;

        vm.prank(address(sm));
        wallet.payRescueBounty(gid, attemptId);

        assertEq(stable.balanceOf(p1), 100); // 10% of 1000
        assertEq(stable.balanceOf(p2), 450);
        assertEq(stable.balanceOf(p3), 450);

        // escape_stable reserve consumed by full bounty amount.
        (, uint256 es) = wallet.escapeReserve(gid);
        assertEq(es, 1_000);

        // Second payment attempt must revert.
        vm.prank(address(sm));
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.RescueAlreadyPaid.selector, gid, attemptId));
        wallet.payRescueBounty(gid, attemptId);
    }

    function _setSafeHavenShell(bytes32 shellId, address payout) internal {
        ShellRecord memory s;
        s.shell_id = shellId;
        s.bond_status = uint8(BondStatus.BONDED);
        s.assurance_tier = 3;
        s.certificate_id = bytes32(uint256(1));
        s.safehaven_bond_amount = 1;
        s.payout_address = payout;
        shellRegistry.setShell(shellId, s);
    }

    // ─── exitRecovery ───────────────────────────────────────────────────────

    function test_exitRecovery_requiresTEC_andDelegates() public {
        // Use a separate wallet wired to a lightweight SessionManager mock so we can assert delegation.
        SessionManagerExitMock smx = new SessionManagerExitMock(GENESIS_TIME, EPOCH_LEN);
        GhostWallet wx = new GhostWallet(address(smx), address(shellRegistry), address(ghostRegistry), T_POLICY_TIMELOCK);

        bytes32 gid = keccak256("ghost-exit");
        bytes32[] memory rs = new bytes32[](1);
        rs[0] = bytes32(uint256(0xB));

        RecoveryConfig memory rc = RecoveryConfig({
            recovery_set: rs,
            threshold: 1,
            bounty_asset: address(stable),
            bounty_total: 0,
            bps_initiator: 0
        });

        bytes32[] memory allowed = new bytes32[](1);
        allowed[0] = homeShell;

        Policy memory pol = Policy({
            home_shell: homeShell,
            allowed_shells: allowed,
            trusted_shells: new bytes32[](0),
            hot_allowance: 0,
            escape_gas: 0,
            escape_stable: 0,
            guardians: new bytes[](0),
            t_guardian: 0,
            roaming_enabled: false
        });

        vm.prank(owner);
        wx.registerGhost(gid, hex"01", salt, rc, pol);

        // TEC satisfied via home shell.
        SessionState memory s;
        s.session_id = 1;
        s.ghost_id = gid;
        s.shell_id = homeShell;
        smx.setSession(s);

        vm.prank(owner);
        wx.exitRecovery(gid);
        assertTrue(smx.exitCalled());

        // TEC failure.
        bytes32 badShell = keccak256("not-tec");
        _setBondedShell(badShell, 2, bytes32(0));
        s.shell_id = badShell;
        smx.setSession(s);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.TECFailed.selector, gid));
        wx.exitRecovery(gid);
    }

    // ─── Access Control ─────────────────────────────────────────────────────

    function test_accessControl_revertsForNonOwner() public {
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(GhostWallet.NotOwner.selector, ghostId, attacker));
        wallet.openSession(ghostId, homeShell, _sessionParams(address(stable)));
    }

    function _isTrusted(bytes32 gid, bytes32 sid) internal view returns (bool) {
        Policy memory p = wallet.getPolicy(gid);
        for (uint256 i = 0; i < p.trusted_shells.length; i++) {
            if (p.trusted_shells[i] == sid) return true;
        }
        return false;
    }
}
