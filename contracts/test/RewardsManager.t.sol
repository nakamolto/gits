// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {RewardsManager} from "../src/RewardsManager.sol";
import {ShellRecord, GhostRecord, RecoveryConfig} from "../src/types/GITSTypes.sol";
import {IGIT} from "../src/interfaces/IGIT.sol";
import {IReceiptManager} from "../src/interfaces/IReceiptManager.sol";
import {ISessionManager} from "../src/interfaces/ISessionManager.sol";
import {IShellRegistry} from "../src/interfaces/IShellRegistry.sol";

contract MockGIT {
    // Minimal ERC20 + IGIT behavior for RewardsManager tests.

    string public constant name = "GIT";
    string public constant symbol = "GIT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public minter;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor() {
        minter = msg.sender;
    }

    function setMinter(address m) external {
        minter = m;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "NOT_MINTER");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ALLOWANCE");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "BALANCE");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}

contract MockReceiptManager {
    mapping(uint256 => uint256) public pendingDA;

    function setPendingDACount(uint256 epoch, uint256 count) external {
        pendingDA[epoch] = count;
    }

    function pendingDACount(uint256 epoch) external view returns (uint256) {
        return pendingDA[epoch];
    }

    function callRecord(
        RewardsManager rm,
        bytes32 receipt_id,
        uint256 epoch,
        bytes32 ghost_id,
        bytes32 shell_id,
        uint32 su_delivered,
        uint256 weight_q
    ) external {
        rm.recordReceipt(receipt_id, epoch, ghost_id, shell_id, su_delivered, weight_q);
    }
}

contract MockShellRegistry {
    struct ShellLite {
        address payout;
        uint256 registered_epoch;
        uint256 bond_amount;
        uint8 bond_status;
    }

    mapping(bytes32 => ShellLite) internal shells;

    function setShell(bytes32 shell_id, address payout, uint256 registered_epoch, uint256 bond_amount, uint8 bond_status)
        external
    {
        shells[shell_id] = ShellLite({
            payout: payout,
            registered_epoch: registered_epoch,
            bond_amount: bond_amount,
            bond_status: bond_status
        });
    }

    function getShell(bytes32 shell_id) external view returns (ShellRecord memory) {
        ShellLite storage s = shells[shell_id];

        address payout = s.payout;
        uint256 bond_amount = s.bond_amount;
        uint256 registered_epoch = s.registered_epoch;
        uint256 bond_status = uint256(s.bond_status);

        // Return ABI-encoded ShellRecord with empty dynamic fields to keep the mock small.
        assembly {
            let ptr := mload(0x40)

            // Head (15 slots = 480 bytes)
            mstore(ptr, shell_id) // 0 shell_id
            mstore(add(ptr, 32), 480) // 1 identity_pubkey offset
            mstore(add(ptr, 64), 512) // 2 offer_signer_pubkey offset
            mstore(add(ptr, 96), payout) // 3 payout_address
            mstore(add(ptr, 128), 0) // 4 bond_asset
            mstore(add(ptr, 160), bond_amount) // 5 bond_amount
            mstore(add(ptr, 192), bond_status) // 6 bond_status
            mstore(add(ptr, 224), 0) // 7 unbond_start_epoch
            mstore(add(ptr, 256), 0) // 8 unbond_end_epoch
            mstore(add(ptr, 288), 544) // 9 recovery_pubkey offset
            mstore(add(ptr, 320), 0) // 10 safehaven_bond_amount
            mstore(add(ptr, 352), 0) // 11 assurance_tier
            mstore(add(ptr, 384), 0) // 12 certificate_id
            mstore(add(ptr, 416), 0) // 13 capability_hash
            mstore(add(ptr, 448), registered_epoch) // 14 registered_epoch

            // Tail: 3 empty bytes fields (identity, offer_signer, recovery_pubkey)
            mstore(add(ptr, 480), 0)
            mstore(add(ptr, 512), 0)
            mstore(add(ptr, 544), 0)

            mstore(0x40, add(ptr, 576))
            return(ptr, 576)
        }
    }

    function assuranceTier(bytes32) external pure returns (uint8) {
        return 0;
    }
}

contract MockGhostRegistry {
    struct GhostLite {
        address wallet;
        uint256 registered_epoch;
        uint256 bond_amount;
        uint256 unbond_end_epoch;
    }

    mapping(bytes32 => GhostLite) internal ghosts;
    mapping(bytes32 => uint256) public cumulativeRewards;

    address public rewardsManager;

    function setRewardsManager(address rm) external {
        rewardsManager = rm;
    }

    function setGhost(bytes32 ghost_id, address wallet, uint256 registered_epoch, uint256 bond_amount, uint256 unbond_end_epoch)
        external
    {
        ghosts[ghost_id] = GhostLite({
            wallet: wallet,
            registered_epoch: registered_epoch,
            bond_amount: bond_amount,
            unbond_end_epoch: unbond_end_epoch
        });
    }

    function getGhost(bytes32 ghost_id) external view returns (GhostRecord memory) {
        GhostLite storage g = ghosts[ghost_id];

        address wallet = g.wallet;
        uint256 registered_epoch = g.registered_epoch;
        uint256 bond_amount = g.bond_amount;
        uint256 unbond_end_epoch = g.unbond_end_epoch;

        // Return ABI-encoded GhostRecord with empty dynamic fields.
        // GhostRecord has 13 head slots (416 bytes) and 4 dynamic fields:
        // identity_pubkey (bytes), recovery_config (tuple with empty array), ptr_checkpoint (bytes), ptr_envelope (bytes).
        assembly {
            let ptr := mload(0x40)

            // Head (13 slots = 416 bytes)
            mstore(ptr, ghost_id) // 0 ghost_id
            mstore(add(ptr, 32), 416) // 1 identity_pubkey offset
            mstore(add(ptr, 64), wallet) // 2 wallet
            mstore(add(ptr, 96), 448) // 3 recovery_config offset (after identity bytes)
            mstore(add(ptr, 128), 0) // 4 checkpoint_commitment
            mstore(add(ptr, 160), 0) // 5 envelope_commitment
            mstore(add(ptr, 192), 640) // 6 ptr_checkpoint offset
            mstore(add(ptr, 224), 672) // 7 ptr_envelope offset
            mstore(add(ptr, 256), 0) // 8 checkpoint_epoch
            mstore(add(ptr, 288), registered_epoch) // 9 registered_epoch
            mstore(add(ptr, 320), 0) // 10 bond_asset
            mstore(add(ptr, 352), bond_amount) // 11 bond_amount
            mstore(add(ptr, 384), unbond_end_epoch) // 12 unbond_end_epoch

            // Tail #1: identity_pubkey = empty bytes
            mstore(add(ptr, 416), 0)

            // Tail #2: recovery_config (192 bytes total)
            // recovery_config head (5 slots = 160 bytes)
            mstore(add(ptr, 448), 160) // offset to recovery_set array data (relative to recovery_config start)
            mstore(add(ptr, 480), 0) // threshold
            mstore(add(ptr, 512), 0) // bounty_asset
            mstore(add(ptr, 544), 0) // bounty_total
            mstore(add(ptr, 576), 0) // bps_initiator
            // recovery_set array tail: length=0
            mstore(add(ptr, 608), 0)

            // Tail #3: ptr_checkpoint = empty bytes
            mstore(add(ptr, 640), 0)

            // Tail #4: ptr_envelope = empty bytes
            mstore(add(ptr, 672), 0)

            mstore(0x40, add(ptr, 704))
            return(ptr, 704)
        }
    }

    function ghostPassportEligible(bytes32, uint256) external pure returns (bool) {
        return true;
    }

    function recordRewardCredit(bytes32 ghost_id, uint256 amount) external {
        require(msg.sender == rewardsManager, "NOT_RM");
        cumulativeRewards[ghost_id] += amount;
    }
}

contract RewardsManagerTest is Test {
    uint256 internal constant Q64 = uint256(1) << 64;

    MockGIT internal git;
    MockReceiptManager internal receiptManager;
    MockShellRegistry internal shellRegistry;
    MockGhostRegistry internal ghostRegistry;

    RewardsManager internal rm;

    bytes32 internal constant GHOST_ID = bytes32(uint256(0x1111));
    bytes32 internal constant SHELL_ID = bytes32(uint256(0x2222));

    address internal ghostWallet = address(0xA11CE);
    address internal shellPayout = address(0xB0B);

    function _deploy(RewardsManager.RewardsConfig memory cfg) internal {
        git = new MockGIT();
        receiptManager = new MockReceiptManager();
        shellRegistry = new MockShellRegistry();
        ghostRegistry = new MockGhostRegistry();

        RewardsManager.RewardsRefs memory refs = RewardsManager.RewardsRefs({
            git: IGIT(address(git)),
            receiptManager: IReceiptManager(address(receiptManager)),
            sessionManager: ISessionManager(address(0)),
            shellRegistry: IShellRegistry(address(shellRegistry)),
            ghostRegistry: address(ghostRegistry)
        });

        rm = _deployRewardsManager(refs, cfg);

        git.setMinter(address(rm));
        ghostRegistry.setRewardsManager(address(rm));

        shellRegistry.setShell(SHELL_ID, shellPayout, 0, 0, 0);
        ghostRegistry.setGhost(GHOST_ID, ghostWallet, 0, 0, 0);
    }

    function _deployRewardsManager(RewardsManager.RewardsRefs memory refs, RewardsManager.RewardsConfig memory cfg)
        internal
        returns (RewardsManager deployed)
    {
        // Avoid `new RewardsManager(refs, cfg)` to prevent stack-too-deep in the ABI encoder.
        // Both structs are static (no dynamic fields), so constructor args are just word concatenation.
        bytes memory args = new bytes(32 * 28); // 5 refs words + 23 cfg words
        assembly {
            let out := add(args, 32)
            let refsPtr := refs
            let cfgPtr := cfg

            // Copy RewardsRefs (5 words)
            for { let i := 0 } lt(i, 5) { i := add(i, 1) } { mstore(add(out, mul(i, 32)), mload(add(refsPtr, mul(i, 32)))) }

            // Copy RewardsConfig (23 words) after the refs words
            for { let j := 0 } lt(j, 23) { j := add(j, 1) } {
                mstore(add(out, mul(add(5, j), 32)), mload(add(cfgPtr, mul(j, 32))))
            }
        }

        bytes memory creation = type(RewardsManager).creationCode;
        bytes memory init = new bytes(creation.length + args.length);
        assembly {
            let initPtr := add(init, 32)

            // Copy creation code
            let cPtr := add(creation, 32)
            let cLen := mload(creation)
            for { let i := 0 } lt(i, cLen) { i := add(i, 32) } { mstore(add(initPtr, i), mload(add(cPtr, i))) }

            // Copy constructor args after creation code
            let aPtr := add(args, 32)
            let aLen := mload(args)
            let dst := add(initPtr, cLen)
            for { let j := 0 } lt(j, aLen) { j := add(j, 32) } { mstore(add(dst, j), mload(add(aPtr, j))) }
        }
        address addr;
        assembly {
            addr := create(0, add(init, 32), mload(init))
        }
        require(addr != address(0), "DEPLOY_FAIL");
        deployed = RewardsManager(addr);
    }

    function _defaultConfig(uint256 genesisTime) internal pure returns (RewardsManager.RewardsConfig memory cfg) {
        cfg.E_0 = 1_000_000e18;
        cfg.E_TAIL = 10_000e18;
        cfg.HALVING_INTERVAL = 1460;

        cfg.GENESIS_TIME = genesisTime;
        cfg.EPOCH_LEN = 1;
        cfg.EPOCH_FINALIZATION_DELAY = 0;
        cfg.FINALIZATION_GRACE = 0;

        cfg.W_CLAIM = 10;

        cfg.W_UPTIME = 4;
        cfg.SU_UPTIME_EPOCH_MIN = uint32(1);
        cfg.E_uptime_min = uint16(0);

        cfg.SU_TARGET = 1;
        cfg.SU_CAP_PER_SHELL = uint32(1_000_000);

        cfg.ALPHA_BPS = uint16(5000);
        cfg.BETA_BPS = uint16(5000);

        cfg.B_reward_min = 0;
        cfg.T_age = 0;
        cfg.B_ghost_reward_min = 0;
        cfg.T_ghost_age = 0;

        cfg.MIN_WEIGHT_Q = 1;

        cfg.u_sink_start_q = 0;
        cfg.u_sink_full_q = Q64;
        cfg.bps_sink_max = uint16(0);
    }

    function setUp() public {
        uint256 genesis = block.timestamp;
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(genesis);
        _deploy(cfg);
    }

    function test_emissionSchedule_firstHalvings_matchExpected() public {
        // epoch=0 => E_0 + E_TAIL
        // epoch=H => E_0/2 + E_TAIL
        // epoch=2H => E_0/4 + E_TAIL
        uint256 H = 1460;

        receiptManager.callRecord(rm, keccak256("r0"), 0, GHOST_ID, SHELL_ID, 1, Q64);
        receiptManager.callRecord(rm, keccak256("r1"), H, GHOST_ID, SHELL_ID, 1, Q64);
        receiptManager.callRecord(rm, keccak256("r2"), 2 * H, GHOST_ID, SHELL_ID, 1, Q64);

        vm.warp(block.timestamp + 2 * H + 2);

        rm.finalizeEpoch(0);
        rm.finalizeEpoch(H);
        rm.finalizeEpoch(2 * H);

        (, , , , , , uint256 e0, , , , , uint256 m0) = rm.epochs(0);
        (, , , , , , uint256 e1, , , , , uint256 m1) = rm.epochs(H);
        (, , , , , , uint256 e2, , , , , uint256 m2) = rm.epochs(2 * H);

        assertEq(e0, 1_010_000e18);
        assertEq(e1, 510_000e18);
        assertEq(e2, 260_000e18);

        // Full utilization and sink disabled => minted equals E_sched.
        assertEq(m0, e0);
        assertEq(m1, e1);
        assertEq(m2, e2);
    }

    function test_recordReceipt_suCapCliff_secondReceiptIneligible() public {
        // Redeploy with a small per-shell cap.
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(block.timestamp);
        cfg.SU_CAP_PER_SHELL = 100;
        _deploy(cfg);

        bytes32 r0 = keccak256("cap-0");
        bytes32 r1 = keccak256("cap-1");

        receiptManager.callRecord(rm, r0, 0, GHOST_ID, SHELL_ID, 60, Q64);
        receiptManager.callRecord(rm, r1, 0, GHOST_ID, SHELL_ID, 50, Q64);

        // First receipt eligible, second should be ineligible due to cap exceed.
        (bool ex0, , bool elig0, , , , , uint256 w0) = rm.receipts(r0);
        (bool ex1, , bool elig1, , , , , uint256 w1) = rm.receipts(r1);
        assertTrue(ex0);
        assertTrue(ex1);
        assertTrue(elig0);
        assertFalse(elig1);
        assertEq(w0, Q64);
        assertEq(w1, 0);

        (, uint256 totalWeight_q, uint256 suEligible, uint256 receiptCount, , , , , , , , ) = rm.epochs(0);
        assertEq(totalWeight_q, Q64);
        assertEq(suEligible, 60);
        assertEq(receiptCount, 2);
    }

    function test_recordReceipt_afterFinalize_isLateAndDoesNotAffectTotals() public {
        bytes32 r0 = keccak256("late-0");
        bytes32 r1 = keccak256("late-1");

        receiptManager.callRecord(rm, r0, 0, GHOST_ID, SHELL_ID, 1, Q64);

        vm.warp(block.timestamp + 2);
        rm.finalizeEpoch(0);

        (, uint256 totalWeightBefore, uint256 suEligibleBefore, uint256 receiptCountBefore, , , , , , , , ) = rm.epochs(0);

        // Late record should not revert and should store weight=0.
        receiptManager.callRecord(rm, r1, 0, GHOST_ID, SHELL_ID, 1, Q64);
        (bool ex1, , bool elig1, , , , , uint256 w1) = rm.receipts(r1);
        assertTrue(ex1);
        assertFalse(elig1);
        assertEq(w1, 0);

        (, uint256 totalWeightAfter, uint256 suEligibleAfter, uint256 receiptCountAfter, , , , , , , , ) = rm.epochs(0);
        assertEq(totalWeightAfter, totalWeightBefore);
        assertEq(suEligibleAfter, suEligibleBefore);
        assertEq(receiptCountAfter, receiptCountBefore);
    }

    function test_finalizeEpoch_guards_pendingDA_tooEarly_doubleFinalize() public {
        // Too early at current_epoch=0.
        vm.expectRevert();
        rm.finalizeEpoch(0);

        // Pending DA reverts even when time is ok.
        vm.warp(block.timestamp + 1);
        receiptManager.setPendingDACount(0, 1);
        vm.expectRevert();
        rm.finalizeEpoch(0);
        receiptManager.setPendingDACount(0, 0);

        // Succeeds now.
        rm.finalizeEpoch(0);

        // Double finalize reverts.
        vm.expectRevert(abi.encodeWithSelector(RewardsManager.EpochAlreadyFinalized.selector, 0));
        rm.finalizeEpoch(0);
    }

    function test_claim_proRata_andDust_matchesVector() public {
        // Redeploy with SU_TARGET=2_880_000 (vector), sink disabled.
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(block.timestamp);
        cfg.SU_TARGET = 2_880_000;
        _deploy(cfg);

        bytes32 rid = keccak256("dust-vector");
        uint32 su = 144;
        uint256 weight = 288 * Q64;

        receiptManager.callRecord(rm, rid, 0, GHOST_ID, SHELL_ID, su, weight);

        vm.warp(block.timestamp + 2);
        rm.finalizeEpoch(0);

        rm.claimReceiptRewards(rid);

        uint256 expected = 25_249_999_999_999_999_968;

        assertEq(git.balanceOf(ghostWallet), expected);
        assertEq(git.balanceOf(shellPayout), expected);

        // Dust is non-withdrawable and remains on RewardsManager.
        assertEq(git.balanceOf(address(rm)), 64);
    }

    function test_claim_recordsRewardCredit_inGhostRegistry() public {
        // Reuse the dust vector case to get a deterministic amount.
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(block.timestamp);
        cfg.SU_TARGET = 2_880_000;
        _deploy(cfg);

        bytes32 rid = keccak256("credit");
        uint32 su = 144;
        uint256 weight = 288 * Q64;

        receiptManager.callRecord(rm, rid, 0, GHOST_ID, SHELL_ID, su, weight);

        vm.warp(block.timestamp + 2);
        rm.finalizeEpoch(0);

        rm.claimReceiptRewards(rid);

        uint256 expected = 25_249_999_999_999_999_968;
        assertEq(ghostRegistry.cumulativeRewards(GHOST_ID), expected);
    }

    function test_expiry_andPruneReceipt() public {
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(block.timestamp);
        cfg.W_CLAIM = 2;
        _deploy(cfg);

        bytes32 rid = keccak256("expiry");
        receiptManager.callRecord(rm, rid, 0, GHOST_ID, SHELL_ID, 1, Q64);

        vm.warp(block.timestamp + 2);
        rm.finalizeEpoch(0);

        // Warp to epoch 3 => expired for epoch 0 when W_CLAIM=2 (3 > 0 + 2).
        vm.warp(block.timestamp + 2);

        vm.expectRevert();
        rm.claimReceiptRewards(rid);

        rm.pruneReceipt(rid);

        vm.expectRevert();
        rm.claimReceiptRewards(rid);
    }

    function test_pruneEpoch_afterExpiry_clearsEpochData() public {
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(block.timestamp);
        cfg.W_CLAIM = 1;
        _deploy(cfg);

        receiptManager.callRecord(rm, keccak256("p0"), 0, GHOST_ID, SHELL_ID, 1, Q64);

        vm.warp(block.timestamp + 2);
        rm.finalizeEpoch(0);

        // Move to current_epoch=2 (> 0 + W_CLAIM)
        vm.warp(block.timestamp + 1);
        rm.pruneEpoch(0);

        (bool finalized, , , , , , uint256 eSched, , , , , ) = rm.epochs(0);
        assertFalse(finalized);
        assertEq(eSched, 0);
    }

    function test_preGenesis_revertsOnEpochClockedFunctions() public {
        uint256 genesisFuture = block.timestamp + 100;
        RewardsManager.RewardsConfig memory cfg = _defaultConfig(genesisFuture);
        _deploy(cfg);

        vm.expectRevert(RewardsManager.GenesisNotReached.selector);
        rm.finalizeEpoch(0);

        vm.expectRevert(RewardsManager.GenesisNotReached.selector);
        rm.claimReceiptRewards(keccak256("nope"));

        vm.expectRevert(RewardsManager.GenesisNotReached.selector);
        rm.pruneEpoch(0);

        vm.expectRevert(RewardsManager.GenesisNotReached.selector);
        rm.pruneReceipt(keccak256("nope"));
    }
}
