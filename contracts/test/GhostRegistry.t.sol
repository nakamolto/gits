// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {GhostRegistry} from "../src/GhostRegistry.sol";
import {RecoveryConfig, GhostRecord} from "../src/types/GITSTypes.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract GhostRegistryTest is Test {
    GhostRegistry internal registry;
    MockERC20 internal bondToken;

    address internal wallet = makeAddr("wallet");
    address internal sessionManager = makeAddr("sessionManager");
    address internal rewardsManager = makeAddr("rewardsManager");

    uint256 internal constant GENESIS_TIME = 1_000_000;
    uint256 internal constant EPOCH_LEN = 10;

    uint256 internal constant T_GHOST_AGE = 5;
    uint256 internal constant B_GHOST_REWARD_MIN = 100 ether;
    uint256 internal constant T_UNBOND_GHOST = 3;

    uint256 internal signerSkOld = 0xA11CE;
    uint256 internal signerSkNew = 0xB0B;

    bytes32 internal salt = bytes32(uint256(0xCAFE));

    function setUp() public {
        bondToken = new MockERC20();

        address[] memory assets = new address[](1);
        assets[0] = address(bondToken);

        registry = new GhostRegistry(
            sessionManager,
            rewardsManager,
            GENESIS_TIME,
            EPOCH_LEN,
            T_GHOST_AGE,
            B_GHOST_REWARD_MIN,
            T_UNBOND_GHOST,
            assets
        );

        // Start at epoch 0 (but strictly >= GENESIS_TIME to satisfy epoch derivation).
        vm.warp(GENESIS_TIME + 1);
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    function _encodeK1(address a) internal pure returns (bytes memory) {
        return abi.encode(uint8(1), abi.encode(a));
    }

    function _ghostId(bytes memory identityPubkey, address wallet_, bytes32 salt_) internal pure returns (bytes32) {
        bytes32 tag = keccak256(bytes("GITS_GHOST_ID"));
        return keccak256(abi.encode(tag, identityPubkey, wallet_, salt_));
    }

    function _recoveryConfig1() internal pure returns (RecoveryConfig memory cfg) {
        bytes32[] memory rs = new bytes32[](1);
        rs[0] = bytes32(uint256(1));

        cfg = RecoveryConfig({
            recovery_set: rs,
            threshold: 1,
            bounty_asset: address(0),
            bounty_total: 0,
            bps_initiator: 0
        });
    }

    function _epochNow() internal view returns (uint256) {
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    function _rotationDigest(bytes32 ghost_id, bytes memory newIdentityPubkey) internal view returns (bytes32) {
        bytes32 tag = keccak256(bytes("GITS_GHOST_ROTATE"));
        return keccak256(abi.encode(tag, ghost_id, newIdentityPubkey, block.chainid));
    }

    function _sig(uint256 sk, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ─── Registration ───────────────────────────────────────────────────────

    function test_registerGhost_success() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.ghost_id, gid);
        assertEq(g.wallet, wallet);
        assertEq(g.identity_pubkey, identityPubkey);
        assertEq(g.registered_epoch, _epochNow());
        assertEq(g.recovery_config.threshold, 1);
        assertEq(g.recovery_config.recovery_set.length, 1);
    }

    function test_registerGhost_revertsOnGhostIdMismatch() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 expected = _ghostId(identityPubkey, wallet, salt);
        bytes32 supplied = bytes32(uint256(0x1234));

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.GhostIdMismatch.selector, supplied, expected));
        registry.registerGhost(supplied, identityPubkey, wallet, salt, _recoveryConfig1());
    }

    function test_registerGhost_revertsIfAlreadyRegistered() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.GhostAlreadyRegistered.selector, gid));
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());
    }

    function test_registerGhost_revertsIfSenderNotWallet() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(GhostRegistry.Unauthorized.selector);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());
    }

    function test_registerGhost_revertsOnUnsupportedSigAlg() public {
        // alg=2 (R1), pk_bytes arbitrary
        bytes memory identityPubkey = abi.encode(uint8(2), abi.encode(bytes32(uint256(1)), bytes32(uint256(2))));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.UnsupportedSigAlg.selector, uint8(2)));
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());
    }

    function test_registerGhost_revertsOnInvalidRecoveryConfig() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        RecoveryConfig memory bad = _recoveryConfig1();
        bad.threshold = 0;

        vm.prank(wallet);
        vm.expectRevert(GhostRegistry.InvalidRecoveryConfig.selector);
        registry.registerGhost(gid, identityPubkey, wallet, salt, bad);
    }

    // ─── rotateSigner ───────────────────────────────────────────────────────

    function test_rotateSigner_walletPath_success() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bytes memory newIdentityPubkey = _encodeK1(vm.addr(signerSkNew));
        bytes32 digest = _rotationDigest(gid, newIdentityPubkey);
        bytes memory proof = _sig(signerSkOld, digest);

        vm.prank(wallet);
        registry.rotateSigner(gid, newIdentityPubkey, proof);

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.ghost_id, gid);
        assertEq(g.identity_pubkey, newIdentityPubkey);
    }

    function test_rotateSigner_walletPath_revertsOnBadProof() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bytes memory newIdentityPubkey = _encodeK1(vm.addr(signerSkNew));
        bytes32 digest = _rotationDigest(gid, newIdentityPubkey);
        bytes memory proof = _sig(uint256(0xDEAD), digest); // wrong signer

        vm.prank(wallet);
        vm.expectRevert(GhostRegistry.InvalidProof.selector);
        registry.rotateSigner(gid, newIdentityPubkey, proof);
    }

    function test_rotateSigner_recoveryPath_successWithEmptyProof() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bytes memory newIdentityPubkey = _encodeK1(vm.addr(signerSkNew));

        vm.prank(sessionManager);
        registry.rotateSigner(gid, newIdentityPubkey, "");

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.identity_pubkey, newIdentityPubkey);
    }

    function test_rotateSigner_recoveryPath_revertsOnNonEmptyProof() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bytes memory newIdentityPubkey = _encodeK1(vm.addr(signerSkNew));

        vm.prank(sessionManager);
        vm.expectRevert(GhostRegistry.InvalidProof.selector);
        registry.rotateSigner(gid, newIdentityPubkey, hex"01");
    }

    function test_rotateSigner_revertsForOtherCallers() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(makeAddr("random"));
        vm.expectRevert(GhostRegistry.Unauthorized.selector);
        registry.rotateSigner(gid, _encodeK1(vm.addr(signerSkNew)), "");
    }

    // ─── Bonds / Unbond ─────────────────────────────────────────────────────

    function test_bondGhost_revertsIfAssetNotAllowed() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.AssetNotAllowed.selector, address(0xBEEF)));
        registry.bondGhost(gid, address(0xBEEF), 1);
    }

    function test_bondGhost_revertsIfAmountZero() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(wallet);
        vm.expectRevert(GhostRegistry.InvalidAmount.selector);
        registry.bondGhost(gid, address(bondToken), 0);
    }

    function test_bondGhost_successTransfersFromWallet() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bondToken.mint(wallet, 200 ether);
        vm.startPrank(wallet);
        bondToken.approve(address(registry), 200 ether);
        registry.bondGhost(gid, address(bondToken), 150 ether);
        vm.stopPrank();

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.bond_asset, address(bondToken));
        assertEq(g.bond_amount, 150 ether);
        assertEq(bondToken.balanceOf(address(registry)), 150 ether);
    }

    function test_beginUnbondGhost_revertsIfAlreadyUnbonding() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bondToken.mint(wallet, 200 ether);
        vm.startPrank(wallet);
        bondToken.approve(address(registry), 200 ether);
        registry.bondGhost(gid, address(bondToken), 150 ether);
        registry.beginUnbondGhost(gid, 50 ether);
        uint256 endEpoch = registry.getGhost(gid).unbond_end_epoch;
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.UnbondPending.selector, endEpoch));
        registry.beginUnbondGhost(gid, 50 ether);
        vm.stopPrank();
    }

    function test_finalizeUnbondGhost_revertsBeforeTimerThenSucceeds() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bondToken.mint(wallet, 200 ether);
        vm.startPrank(wallet);
        bondToken.approve(address(registry), 200 ether);
        registry.bondGhost(gid, address(bondToken), 150 ether);
        registry.beginUnbondGhost(gid, 50 ether);

        // Not ready yet
        uint256 endEpoch = registry.getGhost(gid).unbond_end_epoch;
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.UnbondNotReady.selector, endEpoch));
        registry.finalizeUnbondGhost(gid);

        // Warp to end epoch
        uint256 nowEpoch = _epochNow();
        vm.warp(GENESIS_TIME + ((nowEpoch + T_UNBOND_GHOST) * EPOCH_LEN) + 1);

        uint256 balBefore = bondToken.balanceOf(wallet);
        registry.finalizeUnbondGhost(gid);
        uint256 balAfter = bondToken.balanceOf(wallet);
        vm.stopPrank();

        assertEq(balAfter - balBefore, 50 ether);

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.bond_amount, 100 ether);
        assertEq(g.unbond_end_epoch, 0);
    }

    // ─── Eligibility (passport) ─────────────────────────────────────────────

    function test_ghostPassportEligible_falseIfUnregistered() public view {
        assertFalse(registry.ghostPassportEligible(bytes32(uint256(1)), 0));
    }

    function test_ghostPassportEligible_requiresAgeBondAndRewardHistory() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bondToken.mint(wallet, 200 ether);
        vm.startPrank(wallet);
        bondToken.approve(address(registry), 200 ether);
        registry.bondGhost(gid, address(bondToken), 100 ether);
        vm.stopPrank();

        // Still too young at epoch 4
        assertFalse(registry.ghostPassportEligible(gid, 4));

        // Advance to epoch 5 (age gate passes)
        vm.warp(GENESIS_TIME + (5 * EPOCH_LEN) + 1);

        // Reward history still 0
        assertFalse(registry.ghostPassportEligible(gid, 5));

        // Credit rewards
        vm.prank(rewardsManager);
        registry.recordRewardCredit(gid, 100 ether);

        assertTrue(registry.ghostPassportEligible(gid, 5));

        // If bond drops below threshold, ineligible even with reward history
        vm.startPrank(wallet);
        registry.beginUnbondGhost(gid, 1 ether); // any unbonding makes it ineligible (strict)
        vm.stopPrank();
        assertFalse(registry.ghostPassportEligible(gid, 5));
    }

    function test_recordRewardCredit_revertsIfNotRewardsManager() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(makeAddr("notRewards"));
        vm.expectRevert(GhostRegistry.Unauthorized.selector);
        registry.recordRewardCredit(gid, 1);
    }

    function test_recordRewardCredit_revertsIfGhostNotRegistered() public {
        vm.prank(rewardsManager);
        bytes32 gid = bytes32(uint256(1));
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.GhostNotRegistered.selector, gid));
        registry.recordRewardCredit(gid, 1);
    }

    // ─── Checkpoints ─────────────────────────────────────────────────────────

    function test_publishCheckpoint_storesPointersAsIsAndEnforcesWallet() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        bytes memory ptrCkpt = hex"010203";
        bytes memory ptrEnv = hex"abcdef";

        vm.prank(wallet);
        registry.publishCheckpoint(gid, 7, bytes32(uint256(11)), bytes32(uint256(22)), ptrCkpt, ptrEnv);

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.checkpoint_epoch, 7);
        assertEq(g.checkpoint_commitment, bytes32(uint256(11)));
        assertEq(g.envelope_commitment, bytes32(uint256(22)));
        assertEq(g.ptr_checkpoint, ptrCkpt);
        assertEq(g.ptr_envelope, ptrEnv);

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(GhostRegistry.Unauthorized.selector);
        registry.publishCheckpoint(gid, 8, bytes32(uint256(1)), bytes32(uint256(2)), "", "");
    }

    function test_publishCheckpoint_revertsOnDecreasingEpoch() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        vm.prank(wallet);
        registry.publishCheckpoint(gid, 10, bytes32(uint256(1)), bytes32(uint256(2)), "", "");

        vm.prank(wallet);
        vm.expectRevert(GhostRegistry.InvalidEpochClock.selector);
        registry.publishCheckpoint(gid, 9, bytes32(uint256(1)), bytes32(uint256(2)), "", "");
    }

    // ─── Recovery Config Updates ────────────────────────────────────────────

    function test_setRecoveryConfig_walletOnly() public {
        bytes memory identityPubkey = _encodeK1(vm.addr(signerSkOld));
        bytes32 gid = _ghostId(identityPubkey, wallet, salt);

        vm.prank(wallet);
        registry.registerGhost(gid, identityPubkey, wallet, salt, _recoveryConfig1());

        RecoveryConfig memory cfg = _recoveryConfig1();
        bytes32[] memory rs2 = new bytes32[](2);
        rs2[0] = bytes32(uint256(1));
        rs2[1] = bytes32(uint256(2));
        cfg.recovery_set = rs2;
        cfg.threshold = 2;
        cfg.bps_initiator = 10_000;

        vm.prank(makeAddr("notWallet"));
        vm.expectRevert(GhostRegistry.Unauthorized.selector);
        registry.setRecoveryConfig(gid, cfg);

        vm.prank(wallet);
        registry.setRecoveryConfig(gid, cfg);

        GhostRecord memory g = registry.getGhost(gid);
        assertEq(g.recovery_config.recovery_set.length, 2);
        assertEq(g.recovery_config.threshold, 2);
        assertEq(g.recovery_config.bps_initiator, 10_000);
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    function test_getGhost_revertsIfUnregistered() public {
        bytes32 gid = bytes32(uint256(1));
        vm.expectRevert(abi.encodeWithSelector(GhostRegistry.GhostNotRegistered.selector, gid));
        registry.getGhost(gid);
    }
}
