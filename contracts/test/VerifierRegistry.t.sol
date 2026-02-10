// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {VerifierRegistry} from "../src/VerifierRegistry.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract VerifierRegistryTest is Test {
    address internal constant BURN = address(0x000000000000000000000000000000000000dEaD);
    address internal constant SHELL_REGISTRY = address(0x1234);

    function _deploy(
        uint256 k_v,
        uint256 k_v_threshold,
        uint256 t_stake_activation,
        uint256 t_stake_unbond,
        uint256 bps_reward,
        uint256 genesis_time,
        uint256 epoch_len
    ) internal returns (VerifierRegistry reg, MockERC20 stake) {
        stake = new MockERC20();
        reg = new VerifierRegistry(
            k_v,
            k_v_threshold,
            t_stake_activation,
            t_stake_unbond,
            bps_reward,
            BURN,
            address(stake),
            SHELL_REGISTRY,
            genesis_time,
            epoch_len
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sortedSigs(uint256[] memory pks, bytes32 digest) internal view returns (bytes[] memory sigs) {
        uint256 n = pks.length;
        address[] memory signers = new address[](n);
        bytes[] memory sigTmp = new bytes[](n);

        for (uint256 i = 0; i < n; ++i) {
            signers[i] = vm.addr(pks[i]);
            sigTmp[i] = _sign(pks[i], digest);
        }

        // Simple bubble sort (n is tiny in tests).
        for (uint256 i = 0; i < n; ++i) {
            for (uint256 j = 0; j + 1 < n; ++j) {
                if (signers[j] > signers[j + 1]) {
                    (signers[j], signers[j + 1]) = (signers[j + 1], signers[j]);
                    (sigTmp[j], sigTmp[j + 1]) = (sigTmp[j + 1], sigTmp[j]);
                }
            }
        }

        sigs = new bytes[](n);
        for (uint256 i = 0; i < n; ++i) {
            sigs[i] = sigTmp[i];
        }
    }

    function _register(VerifierRegistry reg, MockERC20 stake, uint256 pk, uint256 amount) internal returns (address v) {
        v = vm.addr(pk);
        stake.mint(v, amount);
        vm.startPrank(v);
        stake.approve(address(reg), amount);
        reg.registerVerifier(address(stake), amount);
        vm.stopPrank();
    }

    function _acPayload(
        bytes32 shellId,
        uint8 teeType,
        bytes32 measurementHash,
        bytes32 tcbMin,
        uint256 validFrom,
        uint256 validTo,
        uint8 assuranceTier,
        bytes32 evidenceHash
    ) internal pure returns (bytes memory) {
        return abi.encode(shellId, teeType, measurementHash, tcbMin, validFrom, validTo, assuranceTier, evidenceHash);
    }

    function _acDigest(
        bytes32 shellId,
        uint8 teeType,
        bytes32 measurementHash,
        bytes32 tcbMin,
        uint256 validFrom,
        uint256 validTo,
        uint8 assuranceTier,
        bytes32 evidenceHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes("GITS_AC")),
                block.chainid,
                SHELL_REGISTRY,
                shellId,
                teeType,
                measurementHash,
                tcbMin,
                validFrom,
                validTo,
                assuranceTier,
                evidenceHash
            )
        );
    }

    function testStakeActivationDelay() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 3,
            k_v_threshold: 2,
            t_stake_activation: 2,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);

        uint256 pk = 0xA11CE;
        address v = _register(reg, stake, pk, 100);

        assertEq(reg.stakeScore(v), 0);

        vm.warp(102); // epoch 2
        assertEq(reg.stakeScore(v), 100);
    }

    function testDecreaseAndWithdrawLifecycle() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 3,
            k_v_threshold: 2,
            t_stake_activation: 1,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);
        uint256 pk = 0xB0B;
        address v = _register(reg, stake, pk, 100);

        vm.warp(101); // activation at epoch 1
        assertEq(reg.stakeScore(v), 100);

        vm.prank(v);
        reg.beginDecreaseStake(address(stake), 50);

        assertEq(reg.stakeScore(v), 50);

        vm.prank(v);
        vm.expectRevert(abi.encodeWithSelector(VerifierRegistry.UnbondNotReady.selector, 1, 4));
        reg.withdrawDecreasedStake(address(stake));

        vm.warp(104); // epoch 4

        uint256 balBefore = stake.balanceOf(v);
        vm.prank(v);
        reg.withdrawDecreasedStake(address(stake));

        assertEq(stake.balanceOf(v), balBefore + 50);
        assertEq(reg.stakeScore(v), 50);

        vm.prank(v);
        vm.expectRevert(VerifierRegistry.NoPendingDecrease.selector);
        reg.withdrawDecreasedStake(address(stake));
    }

    function testActiveSetTopKAndTieBreakLowerAddressWins() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 3,
            k_v_threshold: 2,
            t_stake_activation: 0,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);

        uint256 pk0 = 0x100;
        uint256 pk1 = 0x101;
        uint256 pk2 = 0x102;
        uint256 pk3 = 0x103;

        address v0 = _register(reg, stake, pk0, 100);
        address v1 = _register(reg, stake, pk1, 50);
        address v2 = _register(reg, stake, pk2, 10);
        address v3 = _register(reg, stake, pk3, 10);

        // Top 2 are v0,v1. The 3rd slot is a tie between v2 and v3; lower address wins.
        address tieWinner = v2 < v3 ? v2 : v3;
        address tieLoser = v2 < v3 ? v3 : v2;

        assertTrue(reg.isActiveVerifier(v0));
        assertTrue(reg.isActiveVerifier(v1));
        assertTrue(reg.isActiveVerifier(tieWinner));
        assertFalse(reg.isActiveVerifier(tieLoser));
    }

    function testAllowAndRevokeMeasurementWithQuorumsAndNonce() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 5,
            k_v_threshold: 3,
            t_stake_activation: 0,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);

        uint256[5] memory pksArr = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)];
        for (uint256 i = 0; i < 5; ++i) {
            _register(reg, stake, pksArr[i], 100);
        }

        bytes32 mh = keccak256("measurement");

        // Wrong nonce should revert (expected 0).
        {
            bytes32 digestWrongNonce =
                keccak256(abi.encode(keccak256(bytes("GITS_ALLOW_MEASUREMENT")), block.chainid, address(reg), mh, uint8(0), uint64(1)));
            uint256[] memory pks4 = new uint256[](4);
            pks4[0] = 1;
            pks4[1] = 2;
            pks4[2] = 3;
            pks4[3] = 4;
            bytes[] memory sigs4 = _sortedSigs(pks4, digestWrongNonce);
            vm.expectRevert(abi.encodeWithSelector(VerifierRegistry.InvalidNonce.selector, uint64(0), uint64(1)));
            reg.allowMeasurement(mh, 0, 1, sigs4);
        }

        // Allow tier 0 with supermajority (ceil(2*5/3)=4) at nonce 0.
        {
            bytes32 digest =
                keccak256(abi.encode(keccak256(bytes("GITS_ALLOW_MEASUREMENT")), block.chainid, address(reg), mh, uint8(0), uint64(0)));
            uint256[] memory pks4 = new uint256[](4);
            pks4[0] = 1;
            pks4[1] = 2;
            pks4[2] = 3;
            pks4[3] = 4;
            bytes[] memory sigs4 = _sortedSigs(pks4, digest);
            reg.allowMeasurement(mh, 0, 0, sigs4);
            assertTrue(reg.isMeasurementAllowed(mh, 0));
        }

        // Allow tier 1 at nonce 1.
        {
            bytes32 digest =
                keccak256(abi.encode(keccak256(bytes("GITS_ALLOW_MEASUREMENT")), block.chainid, address(reg), mh, uint8(1), uint64(1)));
            uint256[] memory pks4 = new uint256[](4);
            pks4[0] = 2;
            pks4[1] = 3;
            pks4[2] = 4;
            pks4[3] = 5;
            bytes[] memory sigs4 = _sortedSigs(pks4, digest);
            reg.allowMeasurement(mh, 1, 1, sigs4);
            assertTrue(reg.isMeasurementAllowed(mh, 1));
        }

        // Revoke at nonce 2 with threshold=3. Should revoke both tiers.
        {
            bytes32 digest =
                keccak256(abi.encode(keccak256(bytes("GITS_REVOKE_MEASUREMENT")), block.chainid, address(reg), mh, uint64(2)));
            uint256[] memory pks3 = new uint256[](3);
            pks3[0] = 1;
            pks3[1] = 3;
            pks3[2] = 5;
            bytes[] memory sigs3 = _sortedSigs(pks3, digest);
            reg.revokeMeasurement(mh, 2, sigs3);
            assertFalse(reg.isMeasurementAllowed(mh, 0));
            assertFalse(reg.isMeasurementAllowed(mh, 1));
        }
    }

    function testMeasurementSignatureChecks_unsortedDuplicateInactiveAndInsufficient() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 5,
            k_v_threshold: 3,
            t_stake_activation: 0,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);

        // 6 verifiers with equal stake; active set is the lowest 5 addresses.
        uint256[6] memory pksArr = [uint256(11), uint256(12), uint256(13), uint256(14), uint256(15), uint256(16)];
        address[] memory addrs = new address[](6);
        for (uint256 i = 0; i < 6; ++i) {
            addrs[i] = _register(reg, stake, pksArr[i], 100);
        }

        // Find the excluded (highest address) verifier.
        address excluded = addrs[0];
        for (uint256 i = 1; i < 6; ++i) {
            if (addrs[i] > excluded) excluded = addrs[i];
        }

        bytes32 mh = keccak256("measurement2");
        bytes32 digest =
            keccak256(abi.encode(keccak256(bytes("GITS_ALLOW_MEASUREMENT")), block.chainid, address(reg), mh, uint8(0), uint64(0)));

        // Insufficient signatures (<4) should revert.
        {
            uint256[] memory pks3 = new uint256[](3);
            pks3[0] = 11;
            pks3[1] = 12;
            pks3[2] = 13;
            bytes[] memory sigs3 = _sortedSigs(pks3, digest);
            vm.expectRevert(abi.encodeWithSelector(VerifierRegistry.QuorumNotMet.selector, uint256(4), uint256(3)));
            reg.allowMeasurement(mh, 0, 0, sigs3);
        }

        // Unsorted should revert.
        {
            uint256[] memory pks4 = new uint256[](4);
            pks4[0] = 11;
            pks4[1] = 12;
            pks4[2] = 13;
            pks4[3] = 14;
            bytes[] memory sigs4 = _sortedSigs(pks4, digest);
            // Deliberately unsort by swapping.
            (sigs4[0], sigs4[1]) = (sigs4[1], sigs4[0]);
            vm.expectRevert(VerifierRegistry.SignersNotSorted.selector);
            reg.allowMeasurement(mh, 0, 0, sigs4);
        }

        // Duplicate signer should revert (fails strict ordering check).
        {
            bytes[] memory sigsDup = new bytes[](4);
            sigsDup[0] = _sign(11, digest);
            sigsDup[1] = _sign(11, digest);
            sigsDup[2] = _sign(12, digest);
            sigsDup[3] = _sign(13, digest);
            vm.expectRevert(VerifierRegistry.SignersNotSorted.selector);
            reg.allowMeasurement(mh, 0, 0, sigsDup);
        }

        // Inactive signer should revert.
        {
            uint256[] memory pks4 = new uint256[](4);
            pks4[0] = 11;
            pks4[1] = 12;
            pks4[2] = 13;
            pks4[3] = 16; // likely excluded by tie-break

            bytes[] memory sigs4 = _sortedSigs(pks4, digest);
            vm.expectRevert(abi.encodeWithSelector(VerifierRegistry.SignerNotActive.selector, excluded));
            reg.allowMeasurement(mh, 0, 0, sigs4);
        }
    }

    function testEquivocationProofSlashesFullStakeAndUnregisters() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 1,
            k_v_threshold: 1,
            t_stake_activation: 0,
            t_stake_unbond: 3,
            bps_reward: 1000, // 10%
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);

        uint256 verifierPk = 0xABCD;
        address verifier = _register(reg, stake, verifierPk, 100);

        bytes32 shellId = keccak256("shell");

        address challenger = address(0xCAFE);

        bytes memory payloadA = _acPayload(shellId, 1, bytes32(uint256(1)), bytes32(uint256(2)), 1000, 2000, 0, bytes32(uint256(111)));
        bytes memory payloadB = _acPayload(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 1500, 2500, 0, bytes32(uint256(222)));

        bytes memory sigA = _sign(verifierPk, _acDigest(shellId, 1, bytes32(uint256(1)), bytes32(uint256(2)), 1000, 2000, 0, bytes32(uint256(111))));
        bytes memory sigB = _sign(verifierPk, _acDigest(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 1500, 2500, 0, bytes32(uint256(222))));

        vm.prank(challenger);
        reg.proveVerifierEquivocation(verifier, shellId, payloadA, sigA, payloadB, sigB);

        assertEq(stake.balanceOf(challenger), 10);
        assertEq(stake.balanceOf(BURN), 90);
        assertEq(stake.balanceOf(address(reg)), 0);

        assertFalse(reg.isActiveVerifier(verifier));
        vm.expectRevert(VerifierRegistry.NotRegistered.selector);
        reg.stakeScore(verifier);

        // Re-register should work after cleanup.
        stake.mint(verifier, 50);
        vm.startPrank(verifier);
        stake.approve(address(reg), 50);
        reg.registerVerifier(address(stake), 50);
        vm.stopPrank();

        assertEq(reg.stakeScore(verifier), 50);
    }

    function testEquivocationProofNegativeCases() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 1,
            k_v_threshold: 1,
            t_stake_activation: 0,
            t_stake_unbond: 3,
            bps_reward: 1000,
            genesis_time: 100,
            epoch_len: 1
        });

        vm.warp(100);
        uint256 verifierPk = 0xAAAA;
        address verifier = _register(reg, stake, verifierPk, 100);
        bytes32 shellId = keccak256("shell-neg");

        bytes memory payload = _acPayload(shellId, 1, bytes32(uint256(1)), bytes32(uint256(2)), 1000, 2000, 0, bytes32(uint256(111)));
        bytes memory sig = _sign(verifierPk, _acDigest(shellId, 1, bytes32(uint256(1)), bytes32(uint256(2)), 1000, 2000, 0, bytes32(uint256(111))));

        // Identical digests should revert.
        vm.expectRevert(VerifierRegistry.DigestsEqual.selector);
        reg.proveVerifierEquivocation(verifier, shellId, payload, sig, payload, sig);

        // Non-overlapping windows should revert.
        bytes memory payloadNoOverlap = _acPayload(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 3000, 4000, 0, bytes32(uint256(222)));
        bytes memory sigNoOverlap = _sign(verifierPk, _acDigest(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 3000, 4000, 0, bytes32(uint256(222))));
        vm.expectRevert(VerifierRegistry.ValidityNotOverlapping.selector);
        reg.proveVerifierEquivocation(verifier, shellId, payload, sig, payloadNoOverlap, sigNoOverlap);

        // Wrong signer should revert.
        uint256 wrongPk = 0xBBBB;
        bytes memory payloadOverlap = _acPayload(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 1500, 2500, 0, bytes32(uint256(222)));
        bytes memory wrongSig = _sign(wrongPk, _acDigest(shellId, 1, bytes32(uint256(2)), bytes32(uint256(2)), 1500, 2500, 0, bytes32(uint256(222))));
        vm.expectRevert(VerifierRegistry.SignerMismatch.selector);
        reg.proveVerifierEquivocation(verifier, shellId, payload, sig, payloadOverlap, wrongSig);
    }

    function testPreGenesisRevertsEvenAfterRegistration() public {
        (VerifierRegistry reg, MockERC20 stake) = _deploy({
            k_v: 1,
            k_v_threshold: 1,
            t_stake_activation: 0,
            t_stake_unbond: 1,
            bps_reward: 1000,
            genesis_time: 1000,
            epoch_len: 10
        });

        // Register at genesis.
        vm.warp(1000);
        uint256 pk = 0xC0FFEE;
        address v = _register(reg, stake, pk, 10);
        assertEq(reg.stakeScore(v), 10);

        // Warp back before genesis and ensure PRE_GENESIS is enforced.
        vm.warp(999);
        vm.expectRevert(VerifierRegistry.PreGenesis.selector);
        reg.stakeScore(v);
    }
}
