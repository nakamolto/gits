// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {ReceiptManager} from "../src/ReceiptManager.sol";
import {ReceiptCandidate, FraudProof, FinalReceipt} from "../src/types/GITSTypes.sol";
import {ISessionManager} from "../src/interfaces/ISessionManager.sol";
import {IRewardsManager} from "../src/interfaces/IRewardsManager.sol";
import {IShellRegistry} from "../src/interfaces/IShellRegistry.sol";

contract MockRewardsManager {
    bytes32 public last_receipt_id;
    uint256 public last_epoch;
    bytes32 public last_ghost_id;
    bytes32 public last_shell_id;
    uint32 public last_su_delivered;
    uint256 public last_weight_q;

    function recordReceipt(
        bytes32 receipt_id,
        uint256 epoch,
        bytes32 ghost_id,
        bytes32 shell_id,
        uint32 su_delivered,
        uint256 weight_q
    ) external {
        last_receipt_id = receipt_id;
        last_epoch = epoch;
        last_ghost_id = ghost_id;
        last_shell_id = shell_id;
        last_su_delivered = su_delivered;
        last_weight_q = weight_q;
    }
}

contract MockShellRegistry {}

contract MockSessionManager {
    struct SessionStateFull {
        uint256 session_id;
        bytes32 ghost_id;
        bytes32 shell_id;
        uint8 mode;
        uint8 stranded_reason;
        uint256 lease_expiry_epoch;
        uint256 residency_start_epoch;
        uint256 residency_start_epoch_snapshot;
        uint256 residency_tenure_limit_epochs;
        uint256 session_start_epoch;
        uint8 pricing_mode;
        uint8 assurance_tier_snapshot;
        bool staging;
        bool passport_bonus_applies;
        bool pending_migration;
        bytes32 mig_dest_shell_id;
        uint256 mig_dest_session_id;
        uint256 mig_expiry_epoch;
        uint256 end_epoch;
    }

    mapping(uint256 => SessionStateFull) internal _sessions;
    mapping(uint256 => bytes) internal _ghostKey;
    mapping(uint256 => bytes) internal _shellKey;
    mapping(uint256 => address) internal _submitter;

    // settleEpoch spy
    uint256 public last_settle_session_id;
    uint256 public last_settle_epoch;
    uint256 public last_settle_su;
    uint256 public settle_calls;

    function setSession(uint256 sessionId, SessionStateFull memory s) external {
        _sessions[sessionId] = s;
    }

    function setKeys(uint256 sessionId, bytes memory ghost_key, bytes memory shell_key, address submitter) external {
        _ghostKey[sessionId] = ghost_key;
        _shellKey[sessionId] = shell_key;
        _submitter[sessionId] = submitter;
    }

    function getSessionById(uint256 session_id) external view returns (SessionStateFull memory) {
        return _sessions[session_id];
    }

    function getSessionKeys(uint256 session_id)
        external
        view
        returns (bytes memory ghost_key, bytes memory shell_key, address submitter)
    {
        return (_ghostKey[session_id], _shellKey[session_id], _submitter[session_id]);
    }

    function settleEpoch(uint256 session_id, uint256 epoch, uint256 su_delivered) external {
        last_settle_session_id = session_id;
        last_settle_epoch = epoch;
        last_settle_su = su_delivered;
        settle_calls += 1;
    }
}

contract ReceiptManagerTest is Test {
    // Spec vector constants (Section 14.9)
    uint256 internal constant SPEC_CHAIN_ID = 8453;
    uint256 internal constant SPEC_SESSION_ID = 123456789;
    uint256 internal constant SPEC_EPOCH = 42;

    bytes32 internal constant EXPECTED_HB =
        0x346279e72db9f82fa31c03c8fab3278f83b2797b4cdd9b7a2ba879f4bc9da621;

    bytes32 internal constant EXPECTED_LEAF17 =
        0x3bd00fdcc06781ca996db6dfb070370eaf44b54b2e53e15ba53af9cb5a9adc45;

    bytes32 internal constant EXPECTED_LEAF18 =
        0xeea8fec70a6cc83f8921b68392f325c83995bde1edb3ba04b94003adbc06b3aa;

    bytes32 internal constant EXPECTED_NODE =
        0x43b9228b9e0b50ae2cd9318bce993781b6cae6d741785b619af56441008097ff;

    bytes32 internal constant EXPECTED_MINI_ROOT =
        0xb7b7c48afe3c285065cf61d09b7eb454e18e51bed622e22ad2ff758a1b0f7c2a;

    // Tag hashes
    bytes32 internal constant TAG_HEARTBEAT = keccak256(bytes("GITS_HEARTBEAT"));
    bytes32 internal constant TAG_LOG_LEAF = keccak256(bytes("GITS_LOG_LEAF"));
    bytes32 internal constant TAG_LOG_NODE = keccak256(bytes("GITS_LOG_NODE"));

    MockSessionManager internal sm;
    MockRewardsManager internal rm;
    MockShellRegistry internal sr;
    ReceiptManager internal receiptManager;

    // Deployment constants for tests
    uint256 internal genesisTime = 1_000;
    uint256 internal epochLen = 1;

    uint256 internal SUBMISSION_WINDOW = 2;
    uint256 internal CHALLENGE_WINDOW = 2;
    uint256 internal DA_RESPONSE_WINDOW = 2;
    uint256 internal MAX_EXT = 2;

    uint256 internal K = 2;
    uint256 internal N = 4;
    uint256 internal N_PAD = 4;

    uint256 internal B_RECEIPT = 1 ether;
    uint256 internal B_RECEIPT_3P = 2 ether;
    uint256 internal B_CHALLENGE = 0.5 ether;
    uint256 internal B_DA = 0.25 ether;

    uint256 internal BPS_REWARD = 5_000; // 50%
    address internal burnAddr = address(0x000000000000000000000000000000000000dEaD);

    uint128 internal B_PASSPORT_Q = uint128(uint256(1) << 64); // +1.0 => 2x when passport applies
    uint256 internal D = 30;

    // Test identities
    uint256 internal constant G_SK = 0xA11CE;
    uint256 internal constant S_SK = 0xB0B;
    address internal ghostAddr;
    address internal shellAddr;
    address internal sessionSubmitter;
    bytes internal ghostSessionKey;
    bytes internal shellSessionKey;

    uint256 internal sessionId = 1;
    bytes32 internal ghostId = keccak256("ghost");
    bytes32 internal shellId = keccak256("shell");

    function setUp() public {
        vm.chainId(SPEC_CHAIN_ID);
        vm.txGasPrice(0);

        sm = new MockSessionManager();
        rm = new MockRewardsManager();
        sr = new MockShellRegistry();

        ReceiptManager.ConstructorParams memory p = ReceiptManager.ConstructorParams({
            sessionManager: ISessionManager(address(sm)),
            rewardsManager: IRewardsManager(address(rm)),
            shellRegistry: IShellRegistry(address(sr)),
            genesis_time: genesisTime,
            epoch_len: epochLen,
            submission_window: SUBMISSION_WINDOW,
            challenge_window: CHALLENGE_WINDOW,
            da_response_window: DA_RESPONSE_WINDOW,
            max_challenge_extensions: MAX_EXT,
            k: K,
            n: N,
            n_pad: N_PAD,
            b_receipt: B_RECEIPT,
            b_receipt_3p: B_RECEIPT_3P,
            b_challenge: B_CHALLENGE,
            b_da: B_DA,
            bps_challenger_reward: BPS_REWARD,
            burn_address: burnAddr,
            b_passport_q: B_PASSPORT_Q,
            d: D
        });
        receiptManager = new ReceiptManager(p);

        Vm.Wallet memory gw = vm.createWallet(G_SK);
        Vm.Wallet memory sw = vm.createWallet(S_SK);
        ghostAddr = gw.addr;
        shellAddr = sw.addr;
        sessionSubmitter = makeAddr("submitter");

        // Configure a billable, non-staging session.
        MockSessionManager.SessionStateFull memory s;
        s.session_id = sessionId;
        s.ghost_id = ghostId;
        s.shell_id = shellId;
        s.mode = 0;
        s.stranded_reason = 0;
        s.lease_expiry_epoch = 1_000_000;
        s.residency_start_epoch = 1;
        s.residency_start_epoch_snapshot = 1;
        s.residency_tenure_limit_epochs = 1_000_000;
        s.session_start_epoch = 1;
        s.pricing_mode = 0;
        s.assurance_tier_snapshot = 0;
        s.staging = false;
        s.passport_bonus_applies = true;
        s.pending_migration = false;
        s.mig_dest_shell_id = bytes32(0);
        s.mig_dest_session_id = 0;
        s.mig_expiry_epoch = 0;
        s.end_epoch = 0; // 0 means "not ended" in ReceiptManager check

        sm.setSession(sessionId, s);

        ghostSessionKey = abi.encode(uint8(1), _k1UncompressedPubkey(gw.publicKeyX, gw.publicKeyY));
        shellSessionKey = abi.encode(uint8(1), _k1UncompressedPubkey(sw.publicKeyX, sw.publicKeyY));
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, sessionSubmitter);

        vm.deal(sessionSubmitter, 100 ether);
        vm.deal(ghostAddr, 100 ether);
        vm.deal(shellAddr, 100 ether);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Spec vectors (Section 14.9)
    // ─────────────────────────────────────────────────────────────────────────────

    function testVectors_HeartbeatDigest() public pure {
        bytes32 hb = keccak256(abi.encode(TAG_HEARTBEAT, SPEC_CHAIN_ID, SPEC_SESSION_ID, SPEC_EPOCH, uint256(17)));
        assertEq(hb, EXPECTED_HB);
    }

    function testVectors_LeafHash() public pure {
        bytes memory sigG = _bytesRange(0x01, 65); // 0x01..0x41
        bytes memory sigS = _bytesRange(0x65, 65); // 0x65..0xa5

        bytes32 hSigG = keccak256(sigG);
        bytes32 hSigS = keccak256(sigS);

        // Intermediate hashes in the spec should match.
        assertEq(hSigG, 0x752e968b7f3a77a413a39ffce9f0940703720b705679a9617e303f591a695b30);
        assertEq(hSigS, 0xd763f1b001827c81fd63e0481fab326731ad2f2bdc2e61458e10cfc430a7fe00);

        bytes32 leaf = keccak256(
            abi.encode(
                TAG_LOG_LEAF,
                SPEC_CHAIN_ID,
                SPEC_SESSION_ID,
                SPEC_EPOCH,
                uint32(17),
                uint8(1),
                hSigG,
                hSigS
            )
        );
        assertEq(leaf, EXPECTED_LEAF17);
    }

    function testVectors_NodeHash() public pure {
        // leaf 17 (v=1, sigs per Vector D)
        bytes memory sigG = _bytesRange(0x01, 65);
        bytes memory sigS = _bytesRange(0x65, 65);
        bytes32 leaf17 = keccak256(
            abi.encode(
                TAG_LOG_LEAF,
                SPEC_CHAIN_ID,
                SPEC_SESSION_ID,
                SPEC_EPOCH,
                uint32(17),
                uint8(1),
                keccak256(sigG),
                keccak256(sigS)
            )
        );
        assertEq(leaf17, EXPECTED_LEAF17);

        // leaf 18: v=0, empty sigs
        bytes32 leaf18 = keccak256(
            abi.encode(
                TAG_LOG_LEAF,
                SPEC_CHAIN_ID,
                SPEC_SESSION_ID,
                SPEC_EPOCH,
                uint32(18),
                uint8(0),
                keccak256(bytes("")),
                keccak256(bytes(""))
            )
        );
        assertEq(leaf18, EXPECTED_LEAF18);

        // node hash per Vector E
        bytes32 nodeHash = keccak256(abi.encode(TAG_LOG_NODE, leaf17, leaf18, uint32(1), uint32(0)));
        assertEq(nodeHash, EXPECTED_NODE);
    }

    function testVectors_MiniReceiptRoot() public pure {
        // N_PAD = 4, leaves 0..3. i=0 uses Vector D sigs, i=2 uses 65 bytes of 0x22/0x33.
        bytes memory sigG0 = _bytesRange(0x01, 65);
        bytes memory sigS0 = _bytesRange(0x65, 65);
        bytes memory sigG2 = _repeatByte(0x22, 65);
        bytes memory sigS2 = _repeatByte(0x33, 65);

        bytes32 l0 = _leafFor(SPEC_CHAIN_ID, SPEC_SESSION_ID, SPEC_EPOCH, 0, 1, sigG0, sigS0);
        bytes32 l1 = _leafFor(SPEC_CHAIN_ID, SPEC_SESSION_ID, SPEC_EPOCH, 1, 0, bytes(""), bytes(""));
        bytes32 l2 = _leafFor(SPEC_CHAIN_ID, SPEC_SESSION_ID, SPEC_EPOCH, 2, 1, sigG2, sigS2);
        bytes32 l3 = _leafFor(SPEC_CHAIN_ID, SPEC_SESSION_ID, SPEC_EPOCH, 3, 0, bytes(""), bytes(""));

        (bytes32 n0, uint32 s0) = _node(l0, l1, 1, 0);
        (bytes32 n1, uint32 s1) = _node(l2, l3, 1, 0);
        (bytes32 root, uint32 sumRoot) = _node(n0, n1, s0, s1);

        assertEq(root, EXPECTED_MINI_ROOT);
        assertEq(sumRoot, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Functional tests
    // ─────────────────────────────────────────────────────────────────────────────

    function testSubmit_EvictionRefundsBond() public {
        uint256 epoch = 5;
        _warpToEpoch(epoch + 1); // earliest submission epoch

        // submitter1 submits SU=1
        address submitter1 = makeAddr("sub1");
        address submitter2 = makeAddr("sub2");
        address submitter3 = makeAddr("sub3");
        vm.deal(submitter1, 10 ether);
        vm.deal(submitter2, 10 ether);
        vm.deal(submitter3, 10 ether);

        ReceiptCandidate memory c1 = ReceiptCandidate({log_root: bytes32(uint256(1)), su_delivered: 1, log_ptr: ""});
        ReceiptCandidate memory c2 = ReceiptCandidate({log_root: bytes32(uint256(2)), su_delivered: 2, log_ptr: ""});
        ReceiptCandidate memory c3 = ReceiptCandidate({log_root: bytes32(uint256(3)), su_delivered: 3, log_ptr: ""});

        // All are "third-party" unless they are the recorded submitter; configure sessionSubmitter = submitterX before call.
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter1);
        vm.prank(submitter1);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, c1);
        assertEq(submitter1.balance, 9 ether);

        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter2);
        vm.prank(submitter2);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, c2);
        assertEq(submitter2.balance, 9 ether);

        // Third submission should evict c1 and refund its bond immediately.
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter3);
        vm.prank(submitter3);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, c3);

        assertEq(submitter1.balance, 10 ether); // refunded on eviction
        assertEq(submitter3.balance, 9 ether); // bond still locked
    }

    function testFinalize_NoCandidate_SettlesZero() public {
        uint256 epoch = 7;
        // After submission window closes.
        _warpToEpoch(epoch + 1 + SUBMISSION_WINDOW);

        receiptManager.finalizeReceipt(sessionId, epoch);

        assertEq(sm.last_settle_session_id(), sessionId);
        assertEq(sm.last_settle_epoch(), epoch);
        assertEq(sm.last_settle_su(), 0);
        assertEq(rm.last_su_delivered(), 0);

        FinalReceipt memory fr = receiptManager.getFinalReceipt(sessionId, epoch);
        assertEq(fr.su_delivered, 0);
        assertEq(fr.log_root, bytes32(0));
        assertEq(fr.submitter, address(0));
        assertEq(fr.weight_q, 0);
    }

    function testFinalize_PicksBestCandidate_RefundsBonds() public {
        uint256 epoch = 9;
        _warpToEpoch(epoch + 1);

        address sub1 = makeAddr("sub1f");
        address sub2 = makeAddr("sub2f");
        vm.deal(sub1, 10 ether);
        vm.deal(sub2, 10 ether);

        ReceiptCandidate memory low = ReceiptCandidate({log_root: bytes32(uint256(11)), su_delivered: 1, log_ptr: ""});
        ReceiptCandidate memory high = ReceiptCandidate({log_root: bytes32(uint256(22)), su_delivered: 2, log_ptr: ""});

        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, sub1);
        vm.prank(sub1);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, low);
        assertEq(sub1.balance, 9 ether);

        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, sub2);
        vm.prank(sub2);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, high);
        assertEq(sub2.balance, 9 ether);

        // Wait until submission window closed and challenge window expired.
        // Window starts at the best-candidate submission epoch (second submit), so end = (epoch+1) + CHALLENGE_WINDOW.
        _warpToEpoch(epoch + 1 + CHALLENGE_WINDOW);
        _warpToEpoch(epoch + 1 + SUBMISSION_WINDOW); // ensure submission window closed too
        _warpToEpoch(epoch + 1 + SUBMISSION_WINDOW + 1); // strictly beyond

        // Ensure beyond window end.
        _warpToEpoch(epoch + 1 + CHALLENGE_WINDOW + 1);

        receiptManager.finalizeReceipt(sessionId, epoch);

        assertEq(sm.last_settle_su(), 2);
        assertEq(rm.last_su_delivered(), 2);

        // Bonds refunded to winner + runner-up.
        assertEq(sub1.balance, 10 ether);
        assertEq(sub2.balance, 10 ether);

        FinalReceipt memory fr = receiptManager.getFinalReceipt(sessionId, epoch);
        assertEq(fr.su_delivered, 2);
        assertEq(fr.submitter, sub2);
        assertTrue(fr.weight_q > 0);
    }

    function testSubmit_LateReceiptSkipRefund() public {
        uint256 epoch = 11;
        _warpToEpoch(epoch + 1);

        address sub = makeAddr("lateSub");
        vm.deal(sub, 10 ether);

        ReceiptCandidate memory c = ReceiptCandidate({log_root: bytes32(uint256(123)), su_delivered: 1, log_ptr: ""});

        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, sub);
        vm.prank(sub);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, c);

        _warpToEpoch(epoch + 1 + SUBMISSION_WINDOW + CHALLENGE_WINDOW + 1);
        receiptManager.finalizeReceipt(sessionId, epoch);

        uint256 balBefore = sub.balance;
        vm.prank(sub);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, c);
        assertEq(sub.balance, balBefore); // refunded
    }

    function testFraudProof_Succeeds_DisqualifiesAndRewards() public {
        uint256 epoch = 13;
        _warpToEpoch(epoch + 1);

        address submitter = makeAddr("fraudSubmitter");
        address challenger = makeAddr("fraudChallenger");
        vm.deal(submitter, 10 ether);
        vm.deal(challenger, 10 ether);
        vm.deal(burnAddr, 0);

        // Build a 4-leaf log where only i=0 is claimed delivered (v=1) but signatures are invalid.

        bytes memory badSigG = _repeatByte(0x11, 65);
        bytes memory badSigS = _repeatByte(0x22, 65);

        // Leaf 0 commits to bad sig hashes.
        bytes32 l0 = _leafFor(block.chainid, sessionId, epoch, 0, 1, badSigG, badSigS);
        bytes32 l1 = _leafFor(block.chainid, sessionId, epoch, 1, 0, bytes(""), bytes(""));
        bytes32 l2 = _leafFor(block.chainid, sessionId, epoch, 2, 0, bytes(""), bytes(""));
        bytes32 l3 = _leafFor(block.chainid, sessionId, epoch, 3, 0, bytes(""), bytes(""));
        (bytes32 n0, uint32 s0) = _node(l0, l1, 1, 0);
        (bytes32 n1, uint32 s1) = _node(l2, l3, 0, 0);
        (bytes32 root, ) = _node(n0, n1, s0, s1);

        // Submit candidate (bond from submitter via submitter_address path).
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter);
        ReceiptCandidate memory cand = ReceiptCandidate({log_root: root, su_delivered: 1, log_ptr: ""});
        vm.prank(submitter);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, cand);

        // Fraud proof for interval 0.
        bytes32[] memory sibHashes = new bytes32[](2);
        uint32[] memory sibSums = new uint32[](2);
        sibHashes[0] = l1;
        sibSums[0] = 0;
        sibHashes[1] = n1;
        sibSums[1] = s1;

        FraudProof memory proof = FraudProof({
            candidate_id: 1,
            interval_index: 0,
            claimed_v: 1,
            leaf_hash: l0,
            sibling_hashes: sibHashes,
            sibling_sums: sibSums,
            sig_ghost: badSigG,
            sig_shell: badSigS
        });

        uint256 challengerBefore = challenger.balance;
        uint256 burnBefore = burnAddr.balance;

        vm.prank(challenger);
        receiptManager.challengeReceipt{value: B_CHALLENGE}(sessionId, epoch, proof);

        // Challenger gets reward (50% of B_RECEIPT) and gets B_CHALLENGE back.
        assertEq(challenger.balance, challengerBefore + (B_RECEIPT * BPS_REWARD) / 10_000);
        // Remainder burned.
        assertEq(burnAddr.balance, burnBefore + (B_RECEIPT - (B_RECEIPT * BPS_REWARD) / 10_000));
    }

    function testFraudProof_Fails_WhenSignaturesValid_SlashesChallengeBondToSubmitter() public {
        uint256 epoch = 14;
        _warpToEpoch(epoch + 1);

        address submitter = makeAddr("sigValidSubmitter");
        address challenger = makeAddr("sigValidChallenger");
        vm.deal(submitter, 10 ether);
        vm.deal(challenger, 10 ether);

        // Build a 4-leaf log where only i=0 is delivered (v=1) with VALID signatures.
        bytes memory sigG0 = _sign(G_SK, _hbDigest(sessionId, epoch, uint256(0)));
        bytes memory sigS0 = _sign(S_SK, _hbDigest(sessionId, epoch, uint256(0)));

        bytes32 l0 = _leafFor(block.chainid, sessionId, epoch, 0, 1, sigG0, sigS0);
        bytes32 l1 = _leafFor(block.chainid, sessionId, epoch, 1, 0, bytes(""), bytes(""));
        bytes32 l2 = _leafFor(block.chainid, sessionId, epoch, 2, 0, bytes(""), bytes(""));
        bytes32 l3 = _leafFor(block.chainid, sessionId, epoch, 3, 0, bytes(""), bytes(""));
        (bytes32 n0, uint32 s0) = _node(l0, l1, 1, 0);
        (bytes32 n1, uint32 s1) = _node(l2, l3, 0, 0);
        (bytes32 root, ) = _node(n0, n1, s0, s1);

        // Submit candidate (bond from submitter via submitter_address path).
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter);
        ReceiptCandidate memory cand = ReceiptCandidate({log_root: root, su_delivered: 1, log_ptr: ""});
        vm.prank(submitter);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, cand);

        // Challenge proof for interval 0; should fail because signatures are valid (no fraud).
        bytes32[] memory sibHashes = new bytes32[](2);
        uint32[] memory sibSums = new uint32[](2);
        sibHashes[0] = l1;
        sibSums[0] = 0;
        sibHashes[1] = n1;
        sibSums[1] = s1;

        FraudProof memory proof = FraudProof({
            candidate_id: 1,
            interval_index: 0,
            claimed_v: 1,
            leaf_hash: l0,
            sibling_hashes: sibHashes,
            sibling_sums: sibSums,
            sig_ghost: sigG0,
            sig_shell: sigS0
        });

        uint256 submitterBefore = submitter.balance;
        uint256 challengerBefore = challenger.balance;

        vm.prank(challenger);
        receiptManager.challengeReceipt{value: B_CHALLENGE}(sessionId, epoch, proof);

        assertEq(submitter.balance, submitterBefore + B_CHALLENGE);
        assertEq(challenger.balance, challengerBefore - B_CHALLENGE);
    }

    function testFraudProof_Fails_BadMerkleProof_SlashesChallengeBondToSubmitter() public {
        uint256 epoch = 15;
        _warpToEpoch(epoch + 1);

        address submitter = makeAddr("goodSubmitter");
        address challenger = makeAddr("badChallenger");
        vm.deal(submitter, 10 ether);
        vm.deal(challenger, 10 ether);

        // Build trivial root for v0=0.. (all zero)
        bytes32 l0 = _leafFor(block.chainid, sessionId, epoch, 0, 0, bytes(""), bytes(""));
        bytes32 l1 = _leafFor(block.chainid, sessionId, epoch, 1, 0, bytes(""), bytes(""));
        bytes32 l2 = _leafFor(block.chainid, sessionId, epoch, 2, 0, bytes(""), bytes(""));
        bytes32 l3 = _leafFor(block.chainid, sessionId, epoch, 3, 0, bytes(""), bytes(""));
        (bytes32 n0, uint32 s0) = _node(l0, l1, 0, 0);
        (bytes32 n1, uint32 s1) = _node(l2, l3, 0, 0);
        (bytes32 root, ) = _node(n0, n1, s0, s1);

        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter);
        ReceiptCandidate memory cand = ReceiptCandidate({log_root: root, su_delivered: 0, log_ptr: ""});
        vm.prank(submitter);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, cand);

        // Provide an incorrect sibling hash so Stage 1 fails.
        bytes32[] memory sibHashes = new bytes32[](2);
        uint32[] memory sibSums = new uint32[](2);
        sibHashes[0] = bytes32(uint256(123)); // wrong
        sibSums[0] = 0;
        sibHashes[1] = n1;
        sibSums[1] = s1;

        FraudProof memory proof = FraudProof({
            candidate_id: 1,
            interval_index: 0,
            claimed_v: 0,
            leaf_hash: l0,
            sibling_hashes: sibHashes,
            sibling_sums: sibSums,
            sig_ghost: "",
            sig_shell: ""
        });

        uint256 subBefore = submitter.balance;
        vm.prank(challenger);
        receiptManager.challengeReceipt{value: B_CHALLENGE}(sessionId, epoch, proof);

        assertEq(submitter.balance, subBefore + B_CHALLENGE);
    }

    function testDA_ChallengeResponse_PaysResponder() public {
        uint256 epoch = 17;
        _warpToEpoch(epoch + 1);

        address submitter = makeAddr("daSubmitter");
        address daChallenger = makeAddr("daChallenger");
        address responder = makeAddr("daResponder");
        vm.deal(submitter, 10 ether);
        vm.deal(daChallenger, 10 ether);
        vm.deal(responder, 0);

        // Candidate with v0=1, v2=1 using VALID ECDSA sigs so we can also reuse encoded log parsing for K1 (65-byte sigs).
        bytes memory sigG0 = _sign(G_SK, _hbDigest(sessionId, epoch, uint256(0)));
        bytes memory sigS0 = _sign(S_SK, _hbDigest(sessionId, epoch, uint256(0)));
        bytes memory sigG2 = _sign(G_SK, _hbDigest(sessionId, epoch, uint256(2)));
        bytes memory sigS2 = _sign(S_SK, _hbDigest(sessionId, epoch, uint256(2)));

        bytes32 l0 = _leafFor(block.chainid, sessionId, epoch, 0, 1, sigG0, sigS0);
        bytes32 l1 = _leafFor(block.chainid, sessionId, epoch, 1, 0, bytes(""), bytes(""));
        bytes32 l2 = _leafFor(block.chainid, sessionId, epoch, 2, 1, sigG2, sigS2);
        bytes32 l3 = _leafFor(block.chainid, sessionId, epoch, 3, 0, bytes(""), bytes(""));
        (bytes32 n0, uint32 s0) = _node(l0, l1, 1, 0);
        (bytes32 n1, uint32 s1) = _node(l2, l3, 1, 0);
        (bytes32 root, ) = _node(n0, n1, s0, s1);

        ReceiptCandidate memory cand = ReceiptCandidate({log_root: root, su_delivered: 2, log_ptr: "ipfs://x"});
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter);
        vm.prank(submitter);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, cand);

        // DA challenge
        vm.prank(daChallenger);
        receiptManager.challengeReceiptDA{value: B_DA}(sessionId, epoch, 1);
        assertEq(receiptManager.pendingDACount(epoch), 1);

        // Publish encoded log: bitmap 0b0101 = 0x05, sig_pairs in increasing i order (0 then 2).
        bytes memory bitmap = hex"05";
        bytes memory sigPairs = bytes.concat(sigG0, sigS0, sigG2, sigS2);
        bytes memory encoded = bytes.concat(bitmap, sigPairs);

        uint256 responderBefore = responder.balance;
        vm.prank(responder);
        receiptManager.publishReceiptLog(sessionId, epoch, 1, encoded);

        assertEq(receiptManager.pendingDACount(epoch), 0);
        assertEq(responder.balance, responderBefore + B_DA);
    }

    function testDA_Timeout_DisqualifiesAndRewardsChallenger() public {
        uint256 epoch = 19;
        _warpToEpoch(epoch + 1);

        address submitter = makeAddr("daTimeoutSubmitter");
        address daChallenger = makeAddr("daTimeoutChallenger");
        vm.deal(submitter, 10 ether);
        vm.deal(daChallenger, 10 ether);
        vm.deal(burnAddr, 0);

        // Candidate (any root/su=0 works; DA path recompute checks only on response).
        ReceiptCandidate memory cand = ReceiptCandidate({log_root: bytes32(uint256(999)), su_delivered: 0, log_ptr: "ptr"});
        sm.setKeys(sessionId, ghostSessionKey, shellSessionKey, submitter);
        vm.prank(submitter);
        receiptManager.submitReceiptCandidate{value: B_RECEIPT}(sessionId, epoch, cand);

        vm.prank(daChallenger);
        receiptManager.challengeReceiptDA{value: B_DA}(sessionId, epoch, 1);
        assertEq(receiptManager.pendingDACount(epoch), 1);

        // Warp past DA deadline: current epoch at challenge time is epoch+1, deadline = +DA_RESPONSE_WINDOW.
        _warpToEpoch(epoch + 1 + DA_RESPONSE_WINDOW);

        uint256 challBefore = daChallenger.balance;
        uint256 burnBefore = burnAddr.balance;

        vm.prank(makeAddr("anyone"));
        receiptManager.resolveReceiptDA(sessionId, epoch, 1);

        // Challenger gets B_DA back + reward from slashed receipt bond (50% of B_RECEIPT).
        assertEq(daChallenger.balance, challBefore + B_DA + (B_RECEIPT * BPS_REWARD) / 10_000);
        assertEq(burnAddr.balance, burnBefore + (B_RECEIPT - (B_RECEIPT * BPS_REWARD) / 10_000));
        assertEq(receiptManager.pendingDACount(epoch), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test helpers
    // ─────────────────────────────────────────────────────────────────────────────

    function _k1UncompressedPubkey(uint256 x, uint256 y) internal pure returns (bytes memory) {
        // 0x04 || X(32) || Y(32)
        return abi.encodePacked(bytes1(0x04), bytes32(x), bytes32(y));
    }

    function _warpToEpoch(uint256 e) internal {
        vm.warp(genesisTime + e * epochLen);
    }

    function _hbDigest(uint256 sid, uint256 epoch, uint256 i) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_HEARTBEAT, block.chainid, sid, epoch, i));
    }

    function _hbDigest(uint256 session_id, uint256 epoch, uint32 interval_index) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_HEARTBEAT, block.chainid, session_id, epoch, uint256(interval_index)));
    }

    function _sign(uint256 sk, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _leafFor(uint256 chainId, uint256 sid, uint256 epoch, uint32 i, uint8 v, bytes memory sigG, bytes memory sigS)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_LOG_LEAF, chainId, sid, epoch, i, v, keccak256(sigG), keccak256(sigS)));
    }

    function _node(bytes32 hL, bytes32 hR, uint32 sL, uint32 sR) internal pure returns (bytes32, uint32) {
        return (keccak256(abi.encode(TAG_LOG_NODE, hL, hR, sL, sR)), sL + sR);
    }

    function _bytesRange(uint8 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(uint8(start) + uint8(i));
        }
    }

    function _repeatByte(uint8 b, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(b);
        }
    }
}
