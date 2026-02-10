// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {ShellRegistry} from "../src/ShellRegistry.sol";
import {ShellRecord} from "../src/types/GITSTypes.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockVerifierRegistry {
    mapping(address => bool) public active;
    mapping(bytes32 => mapping(uint8 => bool)) public allowed;

    function setActiveVerifier(address verifier, bool isActive) external {
        active[verifier] = isActive;
    }

    function setMeasurementAllowed(bytes32 measurementHash, uint8 tierClass, bool isAllowed) external {
        allowed[measurementHash][tierClass] = isAllowed;
    }

    function isActiveVerifier(address verifier) external view returns (bool) {
        return active[verifier];
    }

    function isMeasurementAllowed(bytes32 measurementHash, uint8 tierClass) external view returns (bool) {
        return allowed[measurementHash][tierClass];
    }
}

contract MockSessionManager {
    mapping(bytes32 => bool) public activeInitiator;

    function setActiveRecoveryInitiator(bytes32 shellId, bool isActive) external {
        activeInitiator[shellId] = isActive;
    }

    function isActiveRecoveryInitiator(bytes32 shellId) external view returns (bool) {
        return activeInitiator[shellId];
    }
}

contract ShellRegistryTest is Test {
    uint256 internal constant GENESIS_TIME = 1_000_000;
    uint256 internal constant EPOCH_LEN = 100;

    uint256 internal constant T_SHELL_KEY_DELAY = 3;
    uint256 internal constant T_UNBOND_SHELL = 5;
    uint256 internal constant T_UNBOND_SAFEHAVEN = 7;
    uint256 internal constant TTL_AC = 30 days;

    uint256 internal constant K_V_THRESHOLD = 2;
    uint256 internal constant K_V_MAX = 5;
    uint256 internal constant F_CERT = 10e18;

    uint256 internal constant B_HOST_MIN = 100e18;
    uint256 internal constant B_SAFEHAVEN_MIN = 500e18;

    uint256 internal constant BPS_SH_CHALLENGER_REWARD = 1_250; // 12.5%

    address internal constant BURN = address(0x000000000000000000000000000000000000dEaD);

    MockERC20 internal bondToken;
    MockERC20 internal feeToken;
    MockVerifierRegistry internal verifierRegistry;
    MockSessionManager internal sessionManager;

    ShellRegistry internal shellRegistry;

    address internal receiptManager;

    function setUp() public {
        vm.warp(GENESIS_TIME + 1);

        bondToken = new MockERC20("Bond", "BOND");
        feeToken = new MockERC20("Fee", "FEE");
        verifierRegistry = new MockVerifierRegistry();
        sessionManager = new MockSessionManager();

        receiptManager = makeAddr("receiptManager");

        address[] memory bondAssets = new address[](1);
        bondAssets[0] = address(bondToken);

        uint8[] memory teeTypes = new uint8[](1);
        teeTypes[0] = 1;

        uint256 supportedSigAlgs = 1 << 1; // K1 only

        ShellRegistry.InitParams memory p = ShellRegistry.InitParams({
            genesis_time: GENESIS_TIME,
            epoch_len: EPOCH_LEN,
            t_shell_key_delay: T_SHELL_KEY_DELAY,
            t_unbond_shell: T_UNBOND_SHELL,
            t_unbond_safehaven: T_UNBOND_SAFEHAVEN,
            ttl_ac_seconds: TTL_AC,
            k_v_threshold: K_V_THRESHOLD,
            k_v_max: K_V_MAX,
            f_cert: F_CERT,
            asset_verifier_stake: address(feeToken),
            b_host_min: B_HOST_MIN,
            b_safehaven_min: B_SAFEHAVEN_MIN,
            bps_sh_challenger_reward: BPS_SH_CHALLENGER_REWARD,
            supported_sig_algs: supportedSigAlgs,
            protocol_burn_address: BURN,
            session_manager: address(sessionManager),
            verifier_registry: address(verifierRegistry),
            receipt_manager: receiptManager
        });

        shellRegistry = new ShellRegistry(p, bondAssets, teeTypes);
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    function _identityPubkey(address k1Addr) internal pure returns (bytes memory) {
        // Canonical identity key encoding (Section 14.1): abi.encode(uint8(1), abi.encode(address))
        return abi.encode(uint8(1), abi.encode(k1Addr));
    }

    function _offerSignerPubkey(address k1Addr) internal pure returns (bytes memory) {
        // Offer signer tagged union (Section 4.4): abi.encode(uint8(1), addr)
        return abi.encode(uint8(1), k1Addr);
    }

    function _shellId(bytes memory identity_pubkey, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes("GITS_SHELL_ID")), identity_pubkey, salt));
    }

    function _sign(uint256 sk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerDigest(
        bytes32 shell_id,
        address payout,
        bytes memory offer_signer_pubkey,
        address bond_asset,
        uint256 bond_amount,
        bytes32 salt,
        uint64 registryNonce,
        uint256 chainId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes("GITS_SHELL_REGISTER")),
                shell_id,
                payout,
                offer_signer_pubkey,
                bond_asset,
                bond_amount,
                salt,
                registryNonce,
                chainId
            )
        );
    }

    function _acDigest(
        address registry,
        bytes32 shell_id,
        uint8 tee_type,
        bytes32 measurement_hash,
        bytes32 tcb_min,
        uint256 valid_from,
        uint256 valid_to,
        uint8 assurance_tier,
        bytes32 evidence_hash,
        uint256 chainId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes("GITS_AC")),
                chainId,
                registry,
                shell_id,
                tee_type,
                measurement_hash,
                tcb_min,
                valid_from,
                valid_to,
                assurance_tier,
                evidence_hash
            )
        );
    }

    function _sortSignatures(address[] memory addrs, bytes[] memory sigs) internal pure {
        uint256 n = addrs.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (sigs[i], sigs[j]) = (sigs[j], sigs[i]);
                }
            }
        }
    }

    // ─── Registration ───────────────────────────────────────────────────────

    function test_registerShell_success() public {
        address registrant = makeAddr("registrant");
        address payout = makeAddr("payout");

        uint256 identitySk = 0xA11CE;
        address identityAddr = vm.addr(identitySk);
        bytes memory identityPubkey = _identityPubkey(identityAddr);

        uint256 offerSk = 0xB0B;
        address offerAddr = vm.addr(offerSk);
        bytes memory offerPubkey = _offerSignerPubkey(offerAddr);

        bytes32 salt = keccak256("salt-1");
        bytes32 sid = _shellId(identityPubkey, salt);

        uint256 bondAmount = B_HOST_MIN;
        bondToken.mint(registrant, bondAmount);

        bytes32 digest = _registerDigest(
            sid,
            payout,
            offerPubkey,
            address(bondToken),
            bondAmount,
            salt,
            0,
            block.chainid
        );
        bytes memory sig = _sign(identitySk, digest);

        vm.startPrank(registrant);
        bondToken.approve(address(shellRegistry), bondAmount);
        shellRegistry.registerShell(
            sid,
            identityPubkey,
            offerPubkey,
            payout,
            salt,
            address(bondToken),
            bondAmount,
            "",
            new bytes[](0),
            sig
        );
        vm.stopPrank();

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(s.shell_id, sid);
        assertEq(s.payout_address, payout);
        assertEq(s.bond_asset, address(bondToken));
        assertEq(s.bond_amount, bondAmount);
        assertEq(s.bond_status, uint8(0)); // BONDED
        assertEq(bondToken.balanceOf(address(shellRegistry)), bondAmount);
        assertEq(shellRegistry.registry_nonce(), 1);
    }

    function test_registerShell_revertsOnShellIdMismatch() public {
        address registrant = makeAddr("registrant");
        address payout = makeAddr("payout");

        uint256 identitySk = 0xA11CE;
        bytes memory identityPubkey = _identityPubkey(vm.addr(identitySk));

        bytes32 salt = keccak256("salt-1");
        bytes32 sid = _shellId(identityPubkey, salt);

        bytes32 wrongSid = bytes32(uint256(sid) + 1);

        bondToken.mint(registrant, B_HOST_MIN);
        vm.startPrank(registrant);
        bondToken.approve(address(shellRegistry), B_HOST_MIN);

        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.InvalidShellId.selector, sid, wrongSid));
        shellRegistry.registerShell(
            wrongSid,
            identityPubkey,
            _offerSignerPubkey(vm.addr(0xB0B)),
            payout,
            salt,
            address(bondToken),
            B_HOST_MIN,
            "",
            new bytes[](0),
            hex""
        );
        vm.stopPrank();
    }

    function test_registerShell_revertsOnBondAssetNotAllowed() public {
        MockERC20 other = new MockERC20("Other", "O");

        address registrant = makeAddr("registrant");
        address payout = makeAddr("payout");

        uint256 identitySk = 0xA11CE;
        address identityAddr = vm.addr(identitySk);
        bytes memory identityPubkey = _identityPubkey(identityAddr);

        bytes32 salt = keccak256("salt-1");
        bytes32 sid = _shellId(identityPubkey, salt);

        uint256 bondAmount = B_HOST_MIN;
        other.mint(registrant, bondAmount);

        bytes32 digest = _registerDigest(
            sid,
            payout,
            _offerSignerPubkey(vm.addr(0xB0B)),
            address(other),
            bondAmount,
            salt,
            0,
            block.chainid
        );
        bytes memory sig = _sign(identitySk, digest);

        vm.startPrank(registrant);
        other.approve(address(shellRegistry), bondAmount);
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.BondAssetNotAllowed.selector, address(other)));
        shellRegistry.registerShell(
            sid,
            identityPubkey,
            _offerSignerPubkey(vm.addr(0xB0B)),
            payout,
            salt,
            address(other),
            bondAmount,
            "",
            new bytes[](0),
            sig
        );
        vm.stopPrank();
    }

    function test_registerShell_revertsOnBadSignature() public {
        address registrant = makeAddr("registrant");
        address payout = makeAddr("payout");

        uint256 identitySk = 0xA11CE;
        address identityAddr = vm.addr(identitySk);
        bytes memory identityPubkey = _identityPubkey(identityAddr);

        bytes32 salt = keccak256("salt-1");
        bytes32 sid = _shellId(identityPubkey, salt);

        uint256 bondAmount = B_HOST_MIN;
        bondToken.mint(registrant, bondAmount);

        bytes32 digest = _registerDigest(
            sid,
            payout,
            _offerSignerPubkey(vm.addr(0xB0B)),
            address(bondToken),
            bondAmount,
            salt,
            0,
            block.chainid
        );

        // Wrong signer
        bytes memory sig = _sign(0xDEAD, digest);

        vm.startPrank(registrant);
        bondToken.approve(address(shellRegistry), bondAmount);
        vm.expectRevert(ShellRegistry.InvalidSignature.selector);
        shellRegistry.registerShell(
            sid,
            identityPubkey,
            _offerSignerPubkey(vm.addr(0xB0B)),
            payout,
            salt,
            address(bondToken),
            bondAmount,
            "",
            new bytes[](0),
            sig
        );
        vm.stopPrank();
    }

    function test_registerShell_registryNonceAntiReplay() public {
        // First shell consumes registry nonce 0 -> 1.
        _registerDefaultShell();

        address registrant = makeAddr("registrant2");
        address payout = makeAddr("payout2");

        uint256 identitySk = 0x2222;
        address identityAddr = vm.addr(identitySk);
        bytes memory identityPubkey = _identityPubkey(identityAddr);

        bytes memory offerPubkey = _offerSignerPubkey(vm.addr(0x3333));

        bytes32 salt = keccak256("salt-2");
        bytes32 sid = _shellId(identityPubkey, salt);

        uint256 bondAmount = B_HOST_MIN;
        bondToken.mint(registrant, bondAmount);

        // Sign with a stale nonce (0) even though registry_nonce is now 1.
        bytes32 staleDigest = _registerDigest(
            sid,
            payout,
            offerPubkey,
            address(bondToken),
            bondAmount,
            salt,
            0,
            block.chainid
        );
        bytes memory staleSig = _sign(identitySk, staleDigest);

        vm.startPrank(registrant);
        bondToken.approve(address(shellRegistry), bondAmount);
        vm.expectRevert(ShellRegistry.InvalidSignature.selector);
        shellRegistry.registerShell(
            sid,
            identityPubkey,
            offerPubkey,
            payout,
            salt,
            address(bondToken),
            bondAmount,
            "",
            new bytes[](0),
            staleSig
        );

        // Now sign with the current registry nonce (1) and succeed.
        uint64 nonce = shellRegistry.registry_nonce();
        assertEq(nonce, 1);
        bytes32 digest = _registerDigest(
            sid,
            payout,
            offerPubkey,
            address(bondToken),
            bondAmount,
            salt,
            nonce,
            block.chainid
        );
        bytes memory sig = _sign(identitySk, digest);

        shellRegistry.registerShell(
            sid,
            identityPubkey,
            offerPubkey,
            payout,
            salt,
            address(bondToken),
            bondAmount,
            "",
            new bytes[](0),
            sig
        );
        vm.stopPrank();
    }

    // ─── Key Rotation ───────────────────────────────────────────────────────

    function test_identityKeyUpdate_timelockedAndPermissionlessConfirm() public {
        (bytes32 sid, uint256 identitySk, address identityAddr) = _registerDefaultShell();

        uint256 newIdentitySk = 0xBEEF;
        bytes memory newIdentityPubkey = _identityPubkey(vm.addr(newIdentitySk));

        uint64 nonce = shellRegistry.shell_key_nonce(sid);
        bytes32 digest = keccak256(
            abi.encode(
                keccak256(bytes("GITS_SHELL_KEY_PROPOSE")),
                sid,
                newIdentityPubkey,
                nonce,
                block.chainid
            )
        );
        bytes memory proof = _sign(identitySk, digest);

        // Propose via third-party relayer
        vm.prank(makeAddr("relayer"));
        shellRegistry.proposeIdentityKeyUpdate(sid, newIdentityPubkey, proof);

        // Too early
        uint256 nowEpoch = shellRegistry.currentEpoch();
        vm.expectRevert(
            abi.encodeWithSelector(ShellRegistry.TimelockNotElapsed.selector, nowEpoch, nowEpoch + T_SHELL_KEY_DELAY)
        );
        shellRegistry.confirmIdentityKeyUpdate(sid);

        // Advance epochs
        vm.warp(block.timestamp + T_SHELL_KEY_DELAY * EPOCH_LEN);

        // Anyone can confirm
        vm.prank(makeAddr("anyone"));
        shellRegistry.confirmIdentityKeyUpdate(sid);

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(keccak256(s.identity_pubkey), keccak256(newIdentityPubkey));

        // Original identity key no longer authorized for identity-holder gated actions.
        vm.prank(identityAddr);
        vm.expectRevert(ShellRegistry.NotAuthorized.selector);
        shellRegistry.updateCapabilityHash(sid, keccak256("cap"));
    }

    function test_offerSignerUpdate_timelockedAndPermissionlessConfirm() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        bytes memory newOffer = _offerSignerPubkey(vm.addr(0x1234));

        vm.prank(identityAddr);
        shellRegistry.proposeOfferSignerUpdate(sid, newOffer);

        uint256 nowEpoch = shellRegistry.currentEpoch();
        vm.expectRevert(
            abi.encodeWithSelector(ShellRegistry.TimelockNotElapsed.selector, nowEpoch, nowEpoch + T_SHELL_KEY_DELAY)
        );
        shellRegistry.confirmOfferSignerUpdate(sid);

        vm.warp(block.timestamp + T_SHELL_KEY_DELAY * EPOCH_LEN);

        vm.prank(makeAddr("anyone"));
        shellRegistry.confirmOfferSignerUpdate(sid);

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(keccak256(s.offer_signer_pubkey), keccak256(newOffer));
    }

    function test_recoveryKeyUpdate_timelockedAndPermissionlessConfirm() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        bytes memory newRecovery = hex"0102030405";

        vm.prank(identityAddr);
        shellRegistry.proposeRecoveryKeyUpdate(sid, newRecovery);

        uint256 nowEpoch = shellRegistry.currentEpoch();
        vm.expectRevert(
            abi.encodeWithSelector(ShellRegistry.TimelockNotElapsed.selector, nowEpoch, nowEpoch + T_SHELL_KEY_DELAY)
        );
        shellRegistry.confirmRecoveryKeyUpdate(sid);

        vm.warp(block.timestamp + T_SHELL_KEY_DELAY * EPOCH_LEN);

        vm.prank(makeAddr("anyone"));
        shellRegistry.confirmRecoveryKeyUpdate(sid);

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(keccak256(s.recovery_pubkey), keccak256(newRecovery));
    }

    function test_tighteningImmediate_offerSignerDisable() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        vm.prank(identityAddr);
        shellRegistry.proposeOfferSignerUpdate(sid, "");

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(s.offer_signer_pubkey.length, 0);
    }

    function test_offerSignerUpdate_revertsWhenPending() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        bytes memory newOffer = _offerSignerPubkey(vm.addr(0x1234));
        vm.prank(identityAddr);
        shellRegistry.proposeOfferSignerUpdate(sid, newOffer);

        vm.prank(identityAddr);
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.ProposalAlreadyPending.selector, sid));
        shellRegistry.proposeOfferSignerUpdate(sid, _offerSignerPubkey(vm.addr(0x5678)));
    }

    // ─── Certificates ───────────────────────────────────────────────────────

    function test_revokeCertificate_dropsTierAndClearsPointer() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        // Set a cert (tier 1) first.
        bytes32 measurement = keccak256("m-revoke");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);
        bytes32 digest = _acDigest(
            address(shellRegistry),
            sid,
            teeType,
            measurement,
            tcbMin,
            validFrom,
            validTo,
            tier,
            evidence,
            block.chainid
        );

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(digest);
        _sortSignatures(verifiers, sigs);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);
        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();

        assertEq(shellRegistry.assuranceTier(sid), 1);

        vm.prank(identityAddr);
        shellRegistry.revokeCertificate(sid);

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(s.certificate_id, bytes32(0));
        assertEq(s.assurance_tier, 0);
        assertEq(shellRegistry.assuranceTier(sid), 0);

        vm.prank(identityAddr);
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.CertificateDoesNotExist.selector, sid));
        shellRegistry.revokeCertificate(sid);
    }

    function test_setCertificate_revertsOnMeasurementNotAllowed() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m-denied");

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.MeasurementNotAllowed.selector, measurement, uint8(0)));
        shellRegistry.setCertificate(sid, certData, new bytes[](0));
    }

    function test_setCertificate_revertsOnTooManyVerifierSignatures() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m-too-many");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        bytes[] memory sigs = new bytes[](K_V_MAX + 1);
        vm.expectRevert(
            abi.encodeWithSelector(ShellRegistry.TooManyVerifierSignatures.selector, sigs.length, K_V_MAX)
        );
        shellRegistry.setCertificate(sid, certData, sigs);
    }

    function test_setCertificate_revertsOnDuplicateSigner() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m-dup");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        bytes32 digest = _acDigest(
            address(shellRegistry),
            sid,
            teeType,
            measurement,
            tcbMin,
            validFrom,
            validTo,
            tier,
            evidence,
            block.chainid
        );

        uint256 verifierSk = 0x9999;
        address verifierAddr = vm.addr(verifierSk);
        verifierRegistry.setActiveVerifier(verifierAddr, true);

        bytes memory sig = _sign(verifierSk, digest);
        bytes[] memory sigs = new bytes[](K_V_THRESHOLD);
        sigs[0] = sig;
        sigs[1] = sig; // duplicate signer

        vm.expectRevert(ShellRegistry.BadVerifierSigOrder.selector);
        shellRegistry.setCertificate(sid, certData, sigs);
    }

    function test_setCertificate_successAndFeeBurned() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);
        verifierRegistry.setMeasurementAllowed(measurement, 1, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 3;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(
            _acDigest(
                address(shellRegistry),
                sid,
                teeType,
                measurement,
                tcbMin,
                validFrom,
                validTo,
                tier,
                evidence,
                block.chainid
            )
        );

        _sortSignatures(verifiers, sigs);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);

        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(s.certificate_id, keccak256(certData));
        assertEq(s.assurance_tier, tier);
        assertEq(feeToken.balanceOf(BURN), F_CERT);
        assertEq(shellRegistry.assuranceTier(sid), 3);
    }

    function test_setCertificate_revertsOnUnsortedSigs() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        bytes32 digest = _acDigest(
            address(shellRegistry),
            sid,
            teeType,
            measurement,
            tcbMin,
            validFrom,
            validTo,
            tier,
            evidence,
            block.chainid
        );

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(digest);
        _sortSignatures(verifiers, sigs);
        // Break the strictly-increasing order invariant.
        (verifiers[0], verifiers[1]) = (verifiers[1], verifiers[0]);
        (sigs[0], sigs[1]) = (sigs[1], sigs[0]);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);

        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        vm.expectRevert(ShellRegistry.BadVerifierSigOrder.selector);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();
    }

    function test_setCertificate_revertsOnInvalidWindow() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp + 1;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(
            _acDigest(
                address(shellRegistry),
                sid,
                teeType,
                measurement,
                tcbMin,
                validFrom,
                validTo,
                tier,
                evidence,
                block.chainid
            )
        );
        _sortSignatures(verifiers, sigs);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);
        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        vm.expectRevert(ShellRegistry.CertificateWindowInvalid.selector);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();
    }

    function test_assuranceTier_returns0AfterExpiry() public {
        (bytes32 sid,,) = _registerDefaultShell();

        bytes32 measurement = keccak256("m");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 2;
        uint8 tier = 1;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(
            _acDigest(
                address(shellRegistry),
                sid,
                teeType,
                measurement,
                tcbMin,
                validFrom,
                validTo,
                tier,
                evidence,
                block.chainid
            )
        );
        _sortSignatures(verifiers, sigs);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);
        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();

        assertEq(shellRegistry.assuranceTier(sid), 1);
        vm.warp(validTo + 1);
        assertEq(shellRegistry.assuranceTier(sid), 0);
    }

    // ─── Bonds ──────────────────────────────────────────────────────────────

    function test_beginAndFinalizeUnbond_hostBond() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        ShellRecord memory beforeS = shellRegistry.getShell(sid);
        assertEq(beforeS.bond_amount, B_HOST_MIN);

        uint256 unbondAmount = 50e18;

        vm.prank(identityAddr);
        shellRegistry.beginUnbond(sid, unbondAmount);

        ShellRecord memory midS = shellRegistry.getShell(sid);
        assertEq(midS.bond_status, uint8(1)); // UNBONDING

        uint256 nowEpoch = shellRegistry.currentEpoch();
        vm.prank(identityAddr);
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.UnbondNotReady.selector, nowEpoch, midS.unbond_end_epoch));
        shellRegistry.finalizeUnbond(sid);

        vm.warp(block.timestamp + T_UNBOND_SHELL * EPOCH_LEN);

        uint256 payoutBalBefore = bondToken.balanceOf(midS.payout_address);
        vm.prank(identityAddr);
        shellRegistry.finalizeUnbond(sid);
        uint256 payoutBalAfter = bondToken.balanceOf(midS.payout_address);

        assertEq(payoutBalAfter - payoutBalBefore, unbondAmount);
        ShellRecord memory afterS = shellRegistry.getShell(sid);
        assertEq(afterS.bond_amount, B_HOST_MIN - unbondAmount);
        assertEq(afterS.bond_status, uint8(0)); // BONDED (remaining > 0)
    }

    function test_safeHavenBondLifecycle_andUnbondGuard() public {
        (bytes32 sid, uint256 identitySk, address identityAddr) = _registerDefaultShell();

        // Set recovery key (timelocked)
        bytes memory recoveryKey = hex"010203";
        vm.prank(identityAddr);
        shellRegistry.proposeRecoveryKeyUpdate(sid, recoveryKey);
        vm.warp(block.timestamp + T_SHELL_KEY_DELAY * EPOCH_LEN);
        shellRegistry.confirmRecoveryKeyUpdate(sid);

        // Set AT3 cert
        _setAT3Cert(sid);

        // Bond safe haven
        bondToken.mint(identityAddr, B_SAFEHAVEN_MIN);
        vm.startPrank(identityAddr);
        bondToken.approve(address(shellRegistry), B_SAFEHAVEN_MIN);
        shellRegistry.bondSafeHaven(sid, B_SAFEHAVEN_MIN);
        vm.stopPrank();

        ShellRecord memory s = shellRegistry.getShell(sid);
        assertEq(s.safehaven_bond_amount, B_SAFEHAVEN_MIN);

        // Unbond guard: active recovery initiator blocks
        sessionManager.setActiveRecoveryInitiator(sid, true);
        vm.prank(identityAddr);
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.SafeHavenGuardActive.selector, sid));
        shellRegistry.beginUnbondSafeHaven(sid);

        sessionManager.setActiveRecoveryInitiator(sid, false);
        vm.prank(identityAddr);
        shellRegistry.beginUnbondSafeHaven(sid);

        uint256 nowEpoch = shellRegistry.currentEpoch();
        vm.prank(identityAddr);
        vm.expectRevert(
            abi.encodeWithSelector(ShellRegistry.UnbondNotReady.selector, nowEpoch, nowEpoch + T_UNBOND_SAFEHAVEN)
        );
        shellRegistry.finalizeUnbondSafeHaven(sid);

        vm.warp(block.timestamp + T_UNBOND_SAFEHAVEN * EPOCH_LEN);
        uint256 payoutBefore = bondToken.balanceOf(s.payout_address);
        vm.prank(identityAddr);
        shellRegistry.finalizeUnbondSafeHaven(sid);
        uint256 payoutAfter = bondToken.balanceOf(s.payout_address);

        assertEq(payoutAfter - payoutBefore, B_SAFEHAVEN_MIN);
        assertEq(shellRegistry.getShell(sid).safehaven_bond_amount, 0);

        // Silence unused warnings
        identitySk;
    }

    // ─── Slashing ───────────────────────────────────────────────────────────

    function test_slashShell_onlyReceiptManager() public {
        (bytes32 sid,,) = _registerDefaultShell();

        vm.expectRevert(ShellRegistry.OnlyReceiptManager.selector);
        shellRegistry.slashShell(sid, 1, keccak256("reason"));

        vm.prank(receiptManager);
        shellRegistry.slashShell(sid, 10e18, keccak256("reason"));

        assertEq(shellRegistry.getShell(sid).bond_amount, B_HOST_MIN - 10e18);
        assertEq(bondToken.balanceOf(BURN), 10e18);
    }

    function test_slashSafeHaven_onlySessionManager_andRewards() public {
        (bytes32 sid,, address identityAddr) = _registerDefaultShell();

        // Set recovery key + AT3 cert + safe haven bond
        vm.prank(identityAddr);
        shellRegistry.proposeRecoveryKeyUpdate(sid, hex"01");
        vm.warp(block.timestamp + T_SHELL_KEY_DELAY * EPOCH_LEN);
        shellRegistry.confirmRecoveryKeyUpdate(sid);
        _setAT3Cert(sid);

        bondToken.mint(identityAddr, B_SAFEHAVEN_MIN);
        vm.startPrank(identityAddr);
        bondToken.approve(address(shellRegistry), B_SAFEHAVEN_MIN);
        shellRegistry.bondSafeHaven(sid, B_SAFEHAVEN_MIN);
        vm.stopPrank();

        address challenger = makeAddr("challenger");
        uint256 slashAmount = 100e18;
        uint256 expectedReward = (slashAmount * BPS_SH_CHALLENGER_REWARD) / 10_000;

        vm.expectRevert(ShellRegistry.OnlySessionManager.selector);
        shellRegistry.slashSafeHaven(sid, slashAmount, challenger);

        vm.prank(address(sessionManager));
        shellRegistry.slashSafeHaven(sid, slashAmount, challenger);

        assertEq(bondToken.balanceOf(challenger), expectedReward);
        assertEq(bondToken.balanceOf(BURN), slashAmount - expectedReward);
        assertEq(shellRegistry.getShell(sid).safehaven_bond_amount, B_SAFEHAVEN_MIN - slashAmount);
    }

    // ─── Views ──────────────────────────────────────────────────────────────

    function test_getShell_revertsForUnregistered() public {
        bytes32 sid = keccak256("nope");
        vm.expectRevert(abi.encodeWithSelector(ShellRegistry.ShellNotRegistered.selector, sid));
        shellRegistry.getShell(sid);
    }

    // ─── Internal Setup Helpers ─────────────────────────────────────────────

    function _registerDefaultShell() internal returns (bytes32 sid, uint256 identitySk, address identityAddr) {
        address registrant = makeAddr("registrant");
        address payout = makeAddr("payout");

        identitySk = 0xA11CE;
        identityAddr = vm.addr(identitySk);
        bytes memory identityPubkey = _identityPubkey(identityAddr);

        bytes memory offerPubkey = _offerSignerPubkey(vm.addr(0xB0B));

        bytes32 salt = keccak256("salt-default");
        sid = _shellId(identityPubkey, salt);

        uint256 bondAmount = B_HOST_MIN;
        bondToken.mint(registrant, bondAmount);

        bytes32 digest = _registerDigest(
            sid,
            payout,
            offerPubkey,
            address(bondToken),
            bondAmount,
            salt,
            shellRegistry.registry_nonce(),
            block.chainid
        );
        bytes memory sig = _sign(identitySk, digest);

        vm.startPrank(registrant);
        bondToken.approve(address(shellRegistry), bondAmount);
        shellRegistry.registerShell(
            sid,
            identityPubkey,
            offerPubkey,
            payout,
            salt,
            address(bondToken),
            bondAmount,
            "",
            new bytes[](0),
            sig
        );
        vm.stopPrank();
    }

    function _makeVerifierSigs(bytes32 digest) internal returns (address[] memory verifiers, bytes[] memory sigs) {
        verifiers = new address[](K_V_THRESHOLD);
        sigs = new bytes[](K_V_THRESHOLD);

        for (uint256 i = 0; i < K_V_THRESHOLD; i++) {
            uint256 sk = 0x1000 + i;
            address v = vm.addr(sk);
            verifiers[i] = v;
            verifierRegistry.setActiveVerifier(v, true);
            sigs[i] = _sign(sk, digest);
        }
    }

    function _setAT3Cert(bytes32 sid) internal {
        bytes32 measurement = keccak256("m-at3");
        verifierRegistry.setMeasurementAllowed(measurement, 0, true);
        verifierRegistry.setMeasurementAllowed(measurement, 1, true);

        uint8 teeType = 1;
        bytes32 tcbMin = bytes32(uint256(1));
        uint256 validFrom = block.timestamp - 10;
        uint256 validTo = block.timestamp + 100;
        uint8 tier = 3;
        bytes32 evidence = keccak256("evidence");

        bytes memory certData = abi.encode(sid, teeType, measurement, tcbMin, validFrom, validTo, tier, evidence);
        bytes32 digest = _acDigest(
            address(shellRegistry),
            sid,
            teeType,
            measurement,
            tcbMin,
            validFrom,
            validTo,
            tier,
            evidence,
            block.chainid
        );

        (address[] memory verifiers, bytes[] memory sigs) = _makeVerifierSigs(digest);
        _sortSignatures(verifiers, sigs);

        address caller = makeAddr("caller");
        feeToken.mint(caller, F_CERT);
        vm.startPrank(caller);
        feeToken.approve(address(shellRegistry), F_CERT);
        shellRegistry.setCertificate(sid, certData, sigs);
        vm.stopPrank();
    }
}
