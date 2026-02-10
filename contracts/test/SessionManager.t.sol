// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {SessionManager} from "src/SessionManager.sol";
import {
    SessionParams,
    SessionState,
    GhostRecord,
    ShellRecord,
    RecoveryConfig,
    Policy,
    RBC,
    AuthSig,
    ShareReceipt,
    SessionMode,
    StrandedReason,
    BondStatus
} from "src/types/GITSTypes.sol";

import {IGhostRegistry} from "src/interfaces/IGhostRegistry.sol";
import {IShellRegistry} from "src/interfaces/IShellRegistry.sol";
import {IVerifierRegistry} from "src/interfaces/IVerifierRegistry.sol";
import {IGhostWallet} from "src/interfaces/IGhostWallet.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20Mock is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract GhostWalletMock {
    mapping(bytes32 => Policy) internal _policy;

    bytes32 public lastPayBountyGhost;
    uint64 public lastPayBountyAttempt;

    function setPolicy(bytes32 ghost_id, Policy calldata p) external {
        _policy[ghost_id] = p;
    }

    function getPolicy(bytes32 ghost_id) external view returns (Policy memory) {
        return _policy[ghost_id];
    }

    function homeShell(bytes32 ghost_id) external view returns (bytes32) {
        return _policy[ghost_id].home_shell;
    }

    function payRescueBounty(bytes32 ghost_id, uint64 attempt_id) external {
        lastPayBountyGhost = ghost_id;
        lastPayBountyAttempt = attempt_id;
    }
}

contract GhostRegistryMock is IGhostRegistry {
    mapping(bytes32 => GhostRecord) internal _ghosts;
    mapping(bytes32 => bool) internal _passportEligible;

    bytes32 public lastRotateGhost;
    bytes public lastRotateNewKey;
    bytes public lastRotateProof;

    function setGhost(bytes32 ghost_id, GhostRecord calldata g) external {
        _ghosts[ghost_id] = g;
    }

    function setRecoverySet(bytes32 ghost_id, bytes32[] calldata rs, uint64 threshold) external {
        _ghosts[ghost_id].recovery_config.recovery_set = rs;
        _ghosts[ghost_id].recovery_config.threshold = threshold;
    }

    function setPassportEligible(bytes32 ghost_id, bool eligible) external {
        _passportEligible[ghost_id] = eligible;
    }

    // ─── IGhostRegistry ────────────────────────────────────────────────────

    function registerGhost(bytes32, bytes calldata, address, bytes32, RecoveryConfig calldata) external pure {
        revert("not implemented");
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

    function rotateSigner(bytes32 ghost_id, bytes calldata new_identity_pubkey, bytes calldata proof) external {
        lastRotateGhost = ghost_id;
        lastRotateNewKey = new_identity_pubkey;
        lastRotateProof = proof;
        _ghosts[ghost_id].identity_pubkey = new_identity_pubkey;
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
        return _ghosts[ghost_id];
    }
}

contract ShellRegistryMock is IShellRegistry {
    mapping(bytes32 => ShellRecord) internal _shells;

    bytes32 public lastSlashedShell;
    uint256 public lastSlashedAmount;
    address public lastSlashChallenger;

    function setShell(bytes32 shell_id, ShellRecord calldata s) external {
        _shells[shell_id] = s;
    }

    // ─── IShellRegistry (only functions used by SessionManager are meaningful) ───

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

    function slashSafeHaven(bytes32 shell_id, uint256 amount, address challenger) external {
        lastSlashedShell = shell_id;
        lastSlashedAmount = amount;
        lastSlashChallenger = challenger;
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

contract SessionManagerHarness is SessionManager {
    constructor(InitParams memory p) SessionManager(p) {}

    function currentEpochPublic() external view returns (uint256) {
        return _currentEpoch();
    }
}

contract SessionManagerTest is Test {
    event NoAnchorsConfigured(bytes32 indexed ghost_id);

    uint256 internal constant GENESIS_TIME = 1_000_000;
    uint256 internal constant EPOCH_LEN = 10;

    uint256 internal constant LEASE_DEFAULT = 5;
    uint256 internal constant T_TRUST_REFRESH = 2;

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

    bytes32 internal ghostId;
    GhostWalletMock internal wallet;
    GhostRegistryMock internal ghostRegistry;
    ShellRegistryMock internal shellRegistry;
    VerifierRegistryMock internal verifierRegistry;
    ERC20Mock internal token;

    SessionManagerHarness internal sm;

    address internal receiptManager = address(0xBEEF);

    // Test actors: shells and verifiers.
    uint256 internal sh1Pk;
    uint256 internal sh2Pk;
    uint256 internal sh3Pk;
    address internal sh1;
    address internal sh2;
    address internal sh3;

    uint256 internal v1Pk;
    uint256 internal v2Pk;
    address internal v1;
    address internal v2;

    function setUp() public {
        ghostId = keccak256("ghost-1");

        token = new ERC20Mock("Mock", "MOCK");
        wallet = new GhostWalletMock();
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

        sm = new SessionManagerHarness(p);

        // Safe Havens + recovery set members (address-derived shell IDs for v1 tests).
        sh1Pk = 0xA11CE;
        sh2Pk = 0xB0B;
        sh3Pk = 0xC0C0;
        sh1 = vm.addr(sh1Pk);
        sh2 = vm.addr(sh2Pk);
        sh3 = vm.addr(sh3Pk);
        vm.deal(sh1, 100 ether);
        vm.deal(sh2, 100 ether);
        vm.deal(sh3, 100 ether);

        v1Pk = 0xD00D;
        v2Pk = 0xD00E;
        v1 = vm.addr(v1Pk);
        v2 = vm.addr(v2Pk);
        verifierRegistry.setActiveVerifier(v1, true);
        verifierRegistry.setActiveVerifier(v2, true);

        verifierRegistry.setMeasurementAllowed(bytes32(uint256(123)), true);

        // Configure ghost record.
        GhostRecord memory g;
        g.ghost_id = ghostId;
        g.wallet = address(wallet);
        g.checkpoint_commitment = bytes32(uint256(111));
        g.envelope_commitment = bytes32(uint256(222));
        g.recovery_config.recovery_set = _rs(sh1, sh2, sh3);
        g.recovery_config.threshold = 2;
        g.recovery_config.bounty_total = 100;
        ghostRegistry.setGhost(ghostId, g);
        ghostRegistry.setPassportEligible(ghostId, true);

        // Configure wallet policy (home shell set per-test).
        Policy memory pol;
        pol.home_shell = bytes32(0);
        pol.trusted_shells = new bytes32[](0);
        wallet.setPolicy(ghostId, pol);

        // Register a default normal shell for session opens.
        _setShell(shellId(address(0xAAAA)), address(0xCAFE), 1, 0, bytes32(uint256(0x1111)));

        // Register safe haven shells (AT3, bonded, with safehaven bond).
        _setShell(shellId(sh1), address(0xB1), 3, 10 ether, bytes32(uint256(0x9999)));
        _setShell(shellId(sh2), address(0xB2), 3, 10 ether, bytes32(uint256(0x9999)));
        _setShell(shellId(sh3), address(0xB3), 3, 10 ether, bytes32(uint256(0x9999)));

        // Seed wallet with tokens for escrow tests.
        token.mint(address(wallet), 1_000_000);
        vm.prank(address(wallet));
        token.approve(address(sm), type(uint256).max);
    }

    // ─── Epoch Helpers ──────────────────────────────────────────────────────

    function warpToEpoch(uint256 e) internal {
        vm.warp(GENESIS_TIME + e * EPOCH_LEN + 1);
    }

    function shellId(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    // ─── Tests ─────────────────────────────────────────────────────────────

    function test_epochClock_genesisOffset() public {
        vm.warp(GENESIS_TIME + 1);
        assertEq(sm.currentEpochPublic(), 0);

        vm.warp(GENESIS_TIME + EPOCH_LEN + 1);
        assertEq(sm.currentEpochPublic(), 1);
    }

    function test_openSession_storesParams_andKeys() public {
        warpToEpoch(0);

        bytes32 shellA = shellId(address(0xAAAA));
        SessionParams memory sp = _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)});

        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, sp);

        SessionState memory st = sm.getSession(ghostId);
        assertEq(st.mode, uint8(SessionMode.NORMAL));
        assertEq(st.shell_id, shellA);
        assertEq(st.session_start_epoch, 0);
        assertEq(st.lease_expiry_epoch, 0 + LEASE_DEFAULT);
        assertTrue(st.passport_bonus_applies);

        (bytes memory gk, bytes memory sk, address sub) = sm.getSessionKeys(st.session_id);
        assertEq(keccak256(gk), keccak256(sp.ghost_session_key));
        assertEq(keccak256(sk), keccak256(sp.shell_session_key));
        assertEq(sub, sp.submitter_address);
    }

    function test_closeSession_setsDwell_andContinuation() public {
        warpToEpoch(0);

        bytes32 shellA = shellId(address(0xAAAA));
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        uint256 firstSessionId = sm.getSession(ghostId).session_id;

        vm.prank(address(wallet));
        sm.closeSession(ghostId);
        SessionState memory closed = sm.getSessionById(firstSessionId);
        assertEq(closed.mode, uint8(SessionMode.STRANDED));
        assertEq(closed.stranded_reason, uint8(StrandedReason.VOLUNTARY_CLOSE));

        // Re-open next epoch on same shell: continuation should preserve residency_start_epoch_snapshot.
        warpToEpoch(1);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        SessionState memory cont = sm.getSession(ghostId);
        assertEq(cont.residency_start_epoch_snapshot, 0);

        // Re-open after a 2-epoch gap: new residency start should reset.
        vm.prank(address(wallet));
        sm.closeSession(ghostId);

        warpToEpoch(4);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        SessionState memory fresh = sm.getSession(ghostId);
        assertEq(fresh.residency_start_epoch_snapshot, 4);
    }

    function test_passportBloom_windowAndRotation() public {
        bytes32 shellA = shellId(address(0xAAAA));

        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        assertTrue(sm.getSession(ghostId).passport_bonus_applies);
        vm.prank(address(wallet));
        sm.closeSession(ghostId);

        // Within the C_PASSPORT window, second open should not apply bonus (Bloom contains).
        warpToEpoch(1);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        assertTrue(!sm.getSession(ghostId).passport_bonus_applies);
        vm.prank(address(wallet));
        sm.closeSession(ghostId);

        // After C_PASSPORT epochs, Bloom ring should have rotated enough to forget the visit.
        warpToEpoch(C_PASSPORT);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        assertTrue(sm.getSession(ghostId).passport_bonus_applies);
    }

    function test_fundNextEpoch_and_settleEpoch_refundAndPay() public {
        bytes32 shellA = shellId(address(0xAAAA));
        warpToEpoch(0);

        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 1000, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        uint256 sid = sm.getSession(ghostId).session_id;

        uint256 balBefore = token.balanceOf(address(wallet));
        vm.prank(address(wallet));
        sm.fundNextEpoch(sid, 1000);
        assertEq(token.balanceOf(address(wallet)), balBefore - 1000);

        // Settle epoch 1: rent=500, refund=500.
        vm.prank(receiptManager);
        sm.settleEpoch(sid, 1, 50);

        // payout address for shellA is 0xCAFE (setUp)
        assertEq(token.balanceOf(address(0xCAFE)), 500);
        assertEq(token.balanceOf(address(wallet)), balBefore - 1000 + 500);
    }

    function test_fundNextEpoch_revertsAfterLeaseExpiry_evenIfNotProcessed() public {
        bytes32 shellA = shellId(address(0xAAAA));
        warpToEpoch(0);

        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 1000, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        uint256 sid = sm.getSession(ghostId).session_id;

        // LEASE_DEFAULT=5 so expiry at epoch 5; warp beyond without calling processExpiry/renewLease.
        warpToEpoch(LEASE_DEFAULT + 1);

        vm.prank(address(wallet));
        vm.expectRevert(abi.encodeWithSelector(SessionManager.SessionExpired.selector, ghostId));
        sm.fundNextEpoch(sid, 1);
    }

    function test_settleEpoch_shortfall_partialPay_noRevert() public {
        bytes32 shellA = shellId(address(0xAAAA));
        warpToEpoch(0);

        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 30, maxSU: 1000, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        uint256 sid = sm.getSession(ghostId).session_id;

        vm.prank(address(wallet));
        sm.fundNextEpoch(sid, 1000);

        // rent=1500, escrow=1000 => pay 1000, refund 0.
        vm.prank(receiptManager);
        sm.settleEpoch(sid, 1, 50);
        assertEq(token.balanceOf(address(0xCAFE)), 1000);
    }

    function test_settleEpoch_onlyReceiptManager() public {
        bytes32 shellA = shellId(address(0xAAAA));
        warpToEpoch(0);

        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 1000, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        uint256 sid = sm.getSession(ghostId).session_id;

        vm.expectRevert(SessionManager.OnlyReceiptManager.selector);
        sm.settleEpoch(sid, 1, 0);
    }

    function test_renewLease_trustRefresh_overdueRequiresAnchor_orNoAnchorsConfigured() public {
        bytes32 shellA = shellId(address(0xAAAA));
        bytes32 nonAnchor = shellId(address(0xBBBB));
        _setShell(nonAnchor, address(0xD00D), 1, 0, bytes32(uint256(0x1111)));

        // Configure anchors: homeShell = shellA (not the session's shell), so renew on nonAnchor will fail when overdue.
        Policy memory pol = wallet.getPolicy(ghostId);
        pol.home_shell = shellA;
        wallet.setPolicy(ghostId, pol);

        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, nonAnchor, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));

        warpToEpoch(3); // last refresh baseline was epoch 0; overdue for T_TRUST_REFRESH=2
        vm.expectRevert(abi.encodeWithSelector(SessionManager.TrustRefreshRequired.selector, ghostId));
        vm.prank(address(wallet));
        sm.renewLease(ghostId);

        // If no anchors configured, renewal should be allowed and emit NoAnchorsConfigured.
        pol.home_shell = bytes32(0);
        wallet.setPolicy(ghostId, pol);
        ghostRegistry.setRecoverySet(ghostId, new bytes32[](0), 0);

        vm.expectEmit(true, false, false, true);
        emit NoAnchorsConfigured(ghostId);
        vm.prank(address(wallet));
        sm.renewLease(ghostId);
    }

    function test_migration_flow_start_openStaging_cancel_finalize() public {
        bytes32 shellA = shellId(address(0xAAAA));
        bytes32 shellB = shellId(address(0xBBBB));
        _setShell(shellB, address(0xBEEF1), 1, 0, bytes32(uint256(0x1111)));

        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));

        bytes memory proof = abi.encodePacked("bundle");
        bytes32 bundleHash = keccak256(proof);

        vm.prank(address(wallet));
        sm.startMigration(ghostId, shellB, bundleHash);

        // Open staging session on destination.
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellB, _sessionParams({price: 11, maxSU: 200, tenure: 20, leaseExpiry: 0, asset: address(token)}));

        SessionState memory parent = sm.getSession(ghostId);
        assertTrue(parent.pending_migration);
        assertEq(parent.mig_dest_shell_id, shellB);
        assertTrue(parent.mig_dest_session_id != 0);

        SessionState memory staging = sm.getSessionById(parent.mig_dest_session_id);
        assertTrue(staging.staging);
        assertEq(staging.shell_id, shellB);

        // Fund staging escrow and then cancel migration: escrow refunded + staging closed.
        uint256 walletBalBefore = token.balanceOf(address(wallet));
        vm.prank(address(wallet));
        sm.fundNextEpoch(staging.session_id, 1234);
        assertEq(token.balanceOf(address(wallet)), walletBalBefore - 1234);

        vm.prank(address(wallet));
        sm.cancelMigration(ghostId);

        assertEq(token.balanceOf(address(wallet)), walletBalBefore); // refunded
        SessionState memory stagingClosed = sm.getSessionById(staging.session_id);
        assertEq(stagingClosed.mode, uint8(SessionMode.STRANDED));

        // Restart migration + staging and finalize before expiry.
        vm.prank(address(wallet));
        sm.startMigration(ghostId, shellB, bundleHash);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellB, _sessionParams({price: 11, maxSU: 200, tenure: 20, leaseExpiry: 0, asset: address(token)}));

        uint256 parentId = sm.getSession(ghostId).session_id;
        uint256 newStagingId = sm.getSession(ghostId).mig_dest_session_id;
        vm.prank(address(wallet));
        sm.finalizeMigration(ghostId, shellB, proof);

        SessionState memory active = sm.getSession(ghostId);
        assertEq(active.session_id, newStagingId);
        assertTrue(!active.staging);
        SessionState memory oldParent = sm.getSessionById(parentId);
        assertEq(oldParent.mode, uint8(SessionMode.STRANDED));

        // Finalize after expiry should revert.
        vm.prank(address(wallet));
        sm.startMigration(ghostId, shellA, bundleHash);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        warpToEpoch(T_MIGRATION_TIMEOUT + 2);
        vm.expectRevert();
        vm.prank(address(wallet));
        sm.finalizeMigration(ghostId, shellA, proof);
    }

    function test_recovery_flow_rotate_cooldown_exit_and_equivocation() public {
        bytes32 homeShell = shellId(address(0xAAAA));

        // Make current session shell an acceptable TEC target via homeShell.
        Policy memory pol = wallet.getPolicy(ghostId);
        pol.home_shell = homeShell;
        wallet.setPolicy(ghostId, pol);

        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, homeShell, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 100, asset: address(token)}));
        vm.prank(address(wallet));
        sm.closeSession(ghostId); // stranded -> recovery allowed

        // Start recovery by sh1.
        warpToEpoch(1);
        uint256 sh1BalBefore = sh1.balance;
        vm.prank(sh1);
        uint64 attemptId = sm.startRecovery{value: B_START}(ghostId);
        assertEq(uint256(attemptId), 1);
        assertTrue(sm.isActiveRecoveryInitiator(shellId(sh1)));

        // Prepare RBC + signatures.
        bytes memory pkNew = abi.encodePacked("new-identity-key");
        RBC memory rbc = _makeRBC(attemptId, pkNew);

        // RS list must match snapshot.
        bytes32[] memory rsList = _rs(sh1, sh2, sh3);

        // AuthSig: 2-of-3 signatures.
        AuthSig[] memory sigs = new AuthSig[](2);
        bytes32 authDigest = _authDigest(attemptId, ghostRegistry.getGhost(ghostId).checkpoint_commitment, pkNew);
        sigs[0] = AuthSig({shell_id: shellId(sh1), signature: _sig(sh1Pk, authDigest)});
        sigs[1] = AuthSig({shell_id: shellId(sh2), signature: _sig(sh2Pk, authDigest)});

        // ShareReceipts: 2-of-3.
        ShareReceipt[] memory receipts = new ShareReceipt[](2);
        (bytes32 dShare, bytes32 dAck) = _shareDigests(attemptId);
        receipts[0] = ShareReceipt({shell_id: shellId(sh1), sig_shell: _sig(sh1Pk, dShare), sig_ack: _sig(sh1Pk, dAck)});
        receipts[1] = ShareReceipt({shell_id: shellId(sh2), sig_shell: _sig(sh2Pk, dShare), sig_ack: _sig(sh2Pk, dAck)});

        // Rotate at epoch 6 so cooldown is measured from rotate, not start.
        warpToEpoch(6);
        sm.recoveryRotate(ghostId, attemptId, pkNew, rbc, rsList, sigs, receipts);

        // Initiator bond refunded on rotate.
        assertEq(sh1.balance, sh1BalBefore);
        assertTrue(!sm.isActiveRecoveryInitiator(shellId(sh1)));

        SessionState memory st = sm.getSession(ghostId);
        assertEq(st.mode, uint8(SessionMode.RECOVERY_STABILIZING));

        // Ensure GhostRegistry.rotateSigner was invoked and GhostWallet.payRescueBounty was called.
        assertEq(ghostRegistry.lastRotateGhost(), ghostId);
        assertEq(keccak256(ghostRegistry.lastRotateNewKey()), keccak256(pkNew));
        assertEq(wallet.lastPayBountyGhost(), ghostId);
        assertEq(wallet.lastPayBountyAttempt(), attemptId);

        // Exit recovery before cooldown should revert.
        warpToEpoch(7);
        vm.expectRevert();
        vm.prank(address(wallet));
        sm.exitRecovery(ghostId);

        // After cooldown (rotate at epoch 6, cooldown=3 => require epoch >= 9).
        warpToEpoch(9);
        vm.prank(address(wallet));
        sm.exitRecovery(ghostId);
        SessionState memory afterExit = sm.getSession(ghostId);
        assertEq(afterExit.mode, uint8(SessionMode.NORMAL));

        // Prove Safe Haven equivocation and ensure slashing called.
        bytes memory pkA = abi.encodePacked("pk-A");
        bytes memory pkB = abi.encodePacked("pk-B");
        bytes32 cp = ghostRegistry.getGhost(ghostId).checkpoint_commitment;
        bytes32 dA = _recoverAuthDigest(ghostId, attemptId, cp, pkA);
        bytes32 dB = _recoverAuthDigest(ghostId, attemptId, cp, pkB);
        bytes memory sigA = _sig(sh1Pk, dA);
        bytes memory sigB = _sig(sh1Pk, dB);
        uint256 slashAmt = shellRegistry.getShell(shellId(sh1)).safehaven_bond_amount;

        sm.proveSafeHavenEquivocation(shellId(sh1), ghostId, attemptId, cp, pkA, sigA, pkB, sigB);
        assertEq(shellRegistry.lastSlashedShell(), shellId(sh1));
        assertEq(shellRegistry.lastSlashedAmount(), slashAmt);
        assertEq(shellRegistry.lastSlashChallenger(), address(this));
    }

    function test_startRecovery_revertsWhenAlreadyInRecoveryLocked_orStabilizing() public {
        bytes32 shellA = shellId(address(0xAAAA));

        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 100, asset: address(token)}));
        vm.prank(address(wallet));
        sm.closeSession(ghostId);

        // Start recovery by sh1.
        warpToEpoch(1);
        vm.prank(sh1);
        uint64 attemptId = sm.startRecovery{value: B_START}(ghostId);

        // Already RECOVERY_LOCKED: startRecovery should revert (prevents orphaned bond).
        vm.prank(sh2);
        vm.expectRevert(abi.encodeWithSelector(SessionManager.RecoveryNotAllowed.selector, ghostId));
        sm.startRecovery{value: B_START}(ghostId);

        // Rotate to RECOVERY_STABILIZING.
        bytes memory pkNew = abi.encodePacked("new-identity-key-2");
        RBC memory rbc = _makeRBC(attemptId, pkNew);
        bytes32[] memory rsList = _rs(sh1, sh2, sh3);

        AuthSig[] memory sigs = new AuthSig[](2);
        bytes32 authDigest = _authDigest(attemptId, ghostRegistry.getGhost(ghostId).checkpoint_commitment, pkNew);
        sigs[0] = AuthSig({shell_id: shellId(sh1), signature: _sig(sh1Pk, authDigest)});
        sigs[1] = AuthSig({shell_id: shellId(sh2), signature: _sig(sh2Pk, authDigest)});

        ShareReceipt[] memory receipts = new ShareReceipt[](2);
        (bytes32 dShare, bytes32 dAck) = _shareDigests(attemptId);
        receipts[0] = ShareReceipt({shell_id: shellId(sh1), sig_shell: _sig(sh1Pk, dShare), sig_ack: _sig(sh1Pk, dAck)});
        receipts[1] = ShareReceipt({shell_id: shellId(sh2), sig_shell: _sig(sh2Pk, dShare), sig_ack: _sig(sh2Pk, dAck)});

        warpToEpoch(2);
        sm.recoveryRotate(ghostId, attemptId, pkNew, rbc, rsList, sigs, receipts);

        // Already RECOVERY_STABILIZING: startRecovery should revert.
        vm.prank(sh2);
        vm.expectRevert(abi.encodeWithSelector(SessionManager.RecoveryNotAllowed.selector, ghostId));
        sm.startRecovery{value: B_START}(ghostId);
    }

    function test_recovery_expire_and_takeover_liveRS() public {
        bytes32 shellA = shellId(address(0xAAAA));
        warpToEpoch(0);
        vm.prank(address(wallet));
        sm.openSession(ghostId, shellA, _sessionParams({price: 10, maxSU: 100, tenure: 20, leaseExpiry: 0, asset: address(token)}));
        vm.prank(address(wallet));
        sm.closeSession(ghostId);

        // Start recovery by sh1 at epoch 1.
        warpToEpoch(1);
        vm.prank(sh1);
        uint64 attemptId = sm.startRecovery{value: B_START}(ghostId);
        assertEq(uint256(attemptId), 1);

        // Takeover requires epoch >= start + T_RECOVERY_TAKEOVER (2). Start was epoch 1 => require epoch >= 3.
        warpToEpoch(3);

        // Remove sh2 from LIVE recovery set before takeover: takeover by sh2 should revert.
        bytes32[] memory live = new bytes32[](1);
        live[0] = shellId(sh1);
        ghostRegistry.setRecoverySet(ghostId, live, 1);

        vm.prank(sh2);
        vm.expectRevert();
        sm.takeoverRecovery{value: B_START}(ghostId);

        // Restore sh2 into live set and takeover succeeds.
        ghostRegistry.setRecoverySet(ghostId, _rs(sh1, sh2, sh3), 2);

        uint256 sh1Bal = sh1.balance;
        vm.prank(sh2);
        sm.takeoverRecovery{value: B_START}(ghostId);
        assertEq(sh1.balance, sh1Bal + B_START); // old bond refunded
        assertTrue(sm.isActiveRecoveryInitiator(shellId(sh2)));

        // Expire after timeout: start_epoch reset to epoch 3, timeout=4 => require epoch >= 7.
        warpToEpoch(7);
        sm.expireRecovery(ghostId);

        SessionState memory st = sm.getSession(ghostId);
        assertEq(st.mode, uint8(SessionMode.STRANDED));
        assertTrue(!sm.isActiveRecoveryInitiator(shellId(sh2)));
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    function _sessionParams(uint256 price, uint32 maxSU, uint256 tenure, uint256 leaseExpiry, address asset) internal pure returns (SessionParams memory sp) {
        sp.price_per_SU = price;
        sp.max_SU = maxSU;
        sp.lease_expiry_epoch = leaseExpiry;
        sp.tenure_limit_epochs = tenure;
        sp.ghost_session_key = abi.encodePacked("gk");
        sp.shell_session_key = abi.encodePacked("sk");
        sp.submitter_address = address(0x9999);
        sp.asset = asset;
    }

    function _setShell(bytes32 shell_id, address payout, uint8 tier, uint256 safehavenBond, bytes32 certId) internal {
        ShellRecord memory s;
        s.shell_id = shell_id;
        s.payout_address = payout;
        s.bond_status = uint8(BondStatus.BONDED);
        s.safehaven_bond_amount = safehavenBond;
        s.assurance_tier = tier;
        s.certificate_id = certId;
        shellRegistry.setShell(shell_id, s);
    }

    function _rs(address a, address b, address c) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](3);
        out[0] = shellId(a);
        out[1] = shellId(b);
        out[2] = shellId(c);
    }

    function _sig(uint256 pk, bytes32 digest) internal returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _makeRBC(uint64 attemptId, bytes memory pkNew) internal returns (RBC memory rbc) {
        GhostRecord memory g = ghostRegistry.getGhost(ghostId);

        rbc.ghost_id = ghostId;
        rbc.attempt_id = attemptId;
        rbc.checkpoint_commitment = g.checkpoint_commitment;
        rbc.pk_new = pkNew;
        rbc.pk_transport = abi.encodePacked("transport");
        rbc.measurement_hash = bytes32(uint256(123));
        rbc.tcb_min = bytes32(uint256(0xABC));
        rbc.valid_to = block.timestamp + 1000;

        bytes32 digest = keccak256(
            abi.encode(
                keccak256(bytes("GITS_RBC")),
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

        rbc.sigs_verifiers = new bytes[](2);
        rbc.sigs_verifiers[0] = _sig(v1Pk, digest);
        rbc.sigs_verifiers[1] = _sig(v2Pk, digest);
    }

    function _authDigest(uint64 attemptId, bytes32 checkpointCommitment, bytes memory pkNew) internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes("GITS_RECOVER_AUTH")), block.chainid, ghostId, attemptId, checkpointCommitment, keccak256(pkNew)));
    }

    function _shareDigests(uint64 attemptId) internal view returns (bytes32 dShare, bytes32 dAck) {
        GhostRecord memory g = ghostRegistry.getGhost(ghostId);
        dShare = keccak256(
            abi.encode(keccak256(bytes("GITS_SHARE")), block.chainid, ghostId, attemptId, g.checkpoint_commitment, g.envelope_commitment)
        );
        dAck = keccak256(
            abi.encode(keccak256(bytes("GITS_SHARE_ACK")), block.chainid, ghostId, attemptId, g.checkpoint_commitment, g.envelope_commitment)
        );
    }

    function _recoverAuthDigest(bytes32 ghost_id, uint64 attempt_id, bytes32 checkpoint_commitment, bytes memory pk_new) internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes("GITS_RECOVER_AUTH")), block.chainid, ghost_id, attempt_id, checkpoint_commitment, keccak256(pk_new)));
    }
}
