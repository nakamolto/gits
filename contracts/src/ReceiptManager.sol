// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IReceiptManager} from "./interfaces/IReceiptManager.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IRewardsManager} from "./interfaces/IRewardsManager.sol";
import {IShellRegistry} from "./interfaces/IShellRegistry.sol";

import {ReceiptCandidate, FraudProof, FinalReceipt} from "./types/GITSTypes.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

/// @title ReceiptManager — Receipt Candidates, Disputes, and Finalization
/// @notice Implements the receipt submission + dispute + finalization lifecycle (Spec Part 3, Section 14.5).
contract ReceiptManager is IReceiptManager, ReentrancyGuard {
    using Math for uint256;

    // ─────────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────────

    error PreGenesis();
    error InvalidBond();
    error SubmissionWindowClosed();
    error SubmissionTooEarly();
    error ChallengeWindowClosed();
    error DAWindowClosed();
    error DAPending();
    error DANotPending();
    error DAAlreadyPublished();
    error InvalidCandidate();
    error CandidateDisqualified();
    error CandidateEvicted();
    error NotFinalizable();
    error AlreadyFinalized();
    error NotFinalized();
    error UnsupportedSigAlg(uint8 sig_alg);

    // ─────────────────────────────────────────────────────────────────────────────
    // External references
    // ─────────────────────────────────────────────────────────────────────────────

    ISessionManager public immutable sessionManager;
    IRewardsManager public immutable rewardsManager;
    IShellRegistry public immutable shellRegistry;

    // ─────────────────────────────────────────────────────────────────────────────
    // Deployment constants (immutables)
    // ─────────────────────────────────────────────────────────────────────────────

    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    uint256 public immutable SUBMISSION_WINDOW;
    uint256 public immutable CHALLENGE_WINDOW;
    uint256 public immutable DA_RESPONSE_WINDOW;
    uint256 public immutable MAX_CHALLENGE_EXTENSIONS;

    uint256 public immutable T_MAX; // derived per spec (10.5.7)

    uint256 public immutable K; // max candidates per (session, epoch)
    uint256 public immutable N; // intervals per epoch
    uint256 public immutable N_PAD; // padded leaf count (power of two, >= N)

    uint256 public immutable B_RECEIPT;
    uint256 public immutable B_RECEIPT_3P;
    uint256 public immutable B_CHALLENGE;
    uint256 public immutable B_DA;

    uint256 public immutable bps_challenger_reward;
    address public immutable burn_address;

    uint128 public immutable B_PASSPORT_Q; // additive bonus in Q64.64 (0 disables)
    uint256 public immutable D; // dwell decay period (epochs)

    // ─────────────────────────────────────────────────────────────────────────────
    // Hash domain tags (keccak256(bytes(TAG)))
    // ─────────────────────────────────────────────────────────────────────────────

    bytes32 internal constant TAG_HEARTBEAT = keccak256(bytes("GITS_HEARTBEAT"));
    bytes32 internal constant TAG_LOG_LEAF = keccak256(bytes("GITS_LOG_LEAF"));
    bytes32 internal constant TAG_LOG_NODE = keccak256(bytes("GITS_LOG_NODE"));
    bytes32 internal constant TAG_RECEIPT_ID = keccak256(bytes("GITS_RECEIPT"));

    // Q64.64 scaling constant
    uint256 internal constant Q64 = 1 << 64;

    // ─────────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────────

    struct Candidate {
        bytes32 log_root;
        uint32 su_delivered;
        bytes log_ptr;
        address submitter;
        uint256 bond;
        bool disqualified;
        bool evicted;
        bool log_published_onchain;
    }

    struct Window {
        uint256 start_epoch; // current window start (epoch index)
        uint256 end_epoch; // current window end (epoch index)
        uint256 extensions_used;
    }

    struct DAChallenge {
        bool pending;
        uint256 deadline_epoch;
        uint256 candidate_id;
        address challenger;
        uint256 bond;
    }

    struct FinalizationData {
        bytes32 receipt_id;
        bytes32 ghost_id;
        bytes32 shell_id;
        bytes32 log_root;
        uint32 su_delivered;
        address submitter;
        bool shell_reward_eligible;
        uint256 weight_q;
    }

    // candidate_id monotone counter per (session, epoch) for ACCEPTED candidates
    mapping(uint256 session_id => mapping(uint256 epoch => uint256 next_candidate_id)) internal _nextCandidateId;

    // Sorted list of active top-K candidate_ids for (session, epoch)
    mapping(uint256 session_id => mapping(uint256 epoch => uint256[] candidate_ids)) internal _candidateIds;

    // Candidate data
    mapping(uint256 session_id => mapping(uint256 epoch => mapping(uint256 candidate_id => Candidate))) internal _candidates;

    // Challenge window state
    mapping(uint256 session_id => mapping(uint256 epoch => Window)) internal _window;

    // DA challenge state (at most one pending per (session, epoch))
    mapping(uint256 session_id => mapping(uint256 epoch => DAChallenge)) internal _da;

    // Final receipts
    mapping(uint256 session_id => mapping(uint256 epoch => bool finalized)) internal _finalized;
    mapping(uint256 session_id => mapping(uint256 epoch => FinalReceipt receipt)) internal _finalReceipts;

    // O(1) pending DA count per epoch across all sessions (required by IReceiptManager)
    mapping(uint256 epoch => uint256 count) internal _pendingDAByEpoch;

    // ─────────────────────────────────────────────────────────────────────────────
    // SessionState decoding (expects end_epoch appended by SessionManager)
    // ─────────────────────────────────────────────────────────────────────────────

    /// @dev ReceiptManager assumes SessionManager returns a session tuple with `end_epoch` appended
    ///      (spec Section 10.3.5). This avoids modifying shared type files in this worktree.
    struct SessionStateView {
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

    // ─────────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────────

    struct ConstructorParams {
        ISessionManager sessionManager;
        IRewardsManager rewardsManager;
        IShellRegistry shellRegistry;
        uint256 genesis_time;
        uint256 epoch_len;
        uint256 submission_window;
        uint256 challenge_window;
        uint256 da_response_window;
        uint256 max_challenge_extensions;
        uint256 k;
        uint256 n;
        uint256 n_pad;
        uint256 b_receipt;
        uint256 b_receipt_3p;
        uint256 b_challenge;
        uint256 b_da;
        uint256 bps_challenger_reward;
        address burn_address;
        uint128 b_passport_q;
        uint256 d;
    }

    constructor(ConstructorParams memory p) {
        sessionManager = p.sessionManager;
        rewardsManager = p.rewardsManager;
        shellRegistry = p.shellRegistry;

        GENESIS_TIME = p.genesis_time;
        EPOCH_LEN = p.epoch_len;

        SUBMISSION_WINDOW = p.submission_window;
        CHALLENGE_WINDOW = p.challenge_window;
        DA_RESPONSE_WINDOW = p.da_response_window;
        MAX_CHALLENGE_EXTENSIONS = p.max_challenge_extensions;

        K = p.k;
        N = p.n;
        N_PAD = p.n_pad;

        B_RECEIPT = p.b_receipt;
        B_RECEIPT_3P = p.b_receipt_3p;
        B_CHALLENGE = p.b_challenge;
        B_DA = p.b_da;

        bps_challenger_reward = p.bps_challenger_reward;
        burn_address = p.burn_address;

        B_PASSPORT_Q = p.b_passport_q;
        D = p.d;

        // Derived maximum dispute duration (spec 10.5.7)
        T_MAX = p.submission_window
            + (1 + p.max_challenge_extensions) * (p.challenge_window + p.da_response_window);

        // Basic parameter sanity checks (cheap, catches misconfig)
        require(p.epoch_len != 0, "EPOCH_LEN_0");
        require(p.k != 0, "K_0");
        require(p.n != 0, "N_0");
        require(p.n_pad >= p.n, "N_PAD_LT_N");
        require((p.n_pad & (p.n_pad - 1)) == 0, "N_PAD_NOT_POW2");
        require(p.d != 0, "D_0");
        require(p.bps_challenger_reward <= 10_000, "BPS_GT_10000");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────────────

    function pendingDACount(uint256 epoch) external view returns (uint256) {
        return _pendingDAByEpoch[epoch];
    }

    function getFinalReceipt(uint256 session_id, uint256 epoch) external view returns (FinalReceipt memory) {
        if (!_finalized[session_id][epoch]) revert NotFinalized();
        return _finalReceipts[session_id][epoch];
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Receipt submission
    // ─────────────────────────────────────────────────────────────────────────────

    function submitReceiptCandidate(uint256 session_id, uint256 epoch, ReceiptCandidate calldata candidate)
        external
        payable
        nonReentrant
    {
        // Late receipts must silently skip (refund and return).
        if (_finalized[session_id][epoch]) {
            _sendValue(msg.sender, msg.value);
            return;
        }

        uint256 nowEpoch = _currentEpoch();

        // Cannot submit for an epoch that has not ended yet (spec 10.5.2).
        if (nowEpoch < epoch + 1) revert SubmissionTooEarly();

        // Submission window: current_epoch < epoch + 1 + SUBMISSION_WINDOW
        if (nowEpoch >= epoch + 1 + SUBMISSION_WINDOW) revert SubmissionWindowClosed();

        SessionStateView memory s = _getSessionByIdView(session_id);
        // Session must exist and not be staging.
        if (s.session_id != session_id || s.ghost_id == bytes32(0)) revert InvalidCandidate();
        if (s.staging) revert InvalidCandidate();

        // Enforce bond: key-holders or recorded submitter_address pay B_RECEIPT; others pay B_RECEIPT_3P.
        if (msg.value != _requiredReceiptBond(session_id, msg.sender)) revert InvalidBond();

        uint256 tentativeId = _nextCandidateId[session_id][epoch] + 1;

        // Determine if this candidate would land in the top-K set given its SU and tie-break on candidate_id.
        uint256[] storage ids = _candidateIds[session_id][epoch];

        // Fast-path: if full and not better than worst, reject + refund (no revert).
        if (ids.length == K) {
            Candidate storage worst = _candidates[session_id][epoch][ids[ids.length - 1]];
            if (!_isBetter(candidate.su_delivered, tentativeId, worst.su_delivered, ids[ids.length - 1])) {
                _sendValue(msg.sender, msg.value);
                return;
            }
        }

        // Accept: assign candidate_id (monotone for accepted candidates).
        uint256 candidate_id = tentativeId;
        _nextCandidateId[session_id][epoch] = candidate_id;

        Candidate storage c = _candidates[session_id][epoch][candidate_id];
        c.log_root = candidate.log_root;
        c.su_delivered = candidate.su_delivered;
        c.log_ptr = candidate.log_ptr;
        c.submitter = msg.sender;
        c.bond = msg.value;
        c.disqualified = false;
        c.evicted = false;
        c.log_published_onchain = false;

        // Insert into sorted list (su desc, id asc).
        uint256 insertAt = _findInsertPosition(session_id, epoch, candidate.su_delivered, candidate_id);
        ids.push(candidate_id);
        for (uint256 i = ids.length - 1; i > insertAt; i--) {
            ids[i] = ids[i - 1];
        }
        ids[insertAt] = candidate_id;

        // If we exceeded K, evict the worst and return its bond immediately.
        if (ids.length > K) {
            uint256 evictedId = ids[ids.length - 1];
            ids.pop();
            _evictCandidate(session_id, epoch, evictedId);
        }

        // Initialize or update challenge window.
        Window storage w = _window[session_id][epoch];
        if (w.start_epoch == 0 && w.end_epoch == 0) {
            // First accepted candidate.
            w.start_epoch = nowEpoch;
            w.end_epoch = nowEpoch + CHALLENGE_WINDOW;
            w.extensions_used = 0;
        } else if (insertAt == 0) {
            // New best candidate within submission window: restart window (no extension increment).
            w.start_epoch = nowEpoch;
            w.end_epoch = nowEpoch + CHALLENGE_WINDOW;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Fraud proofs
    // ─────────────────────────────────────────────────────────────────────────────

    function challengeReceipt(uint256 session_id, uint256 epoch, FraudProof calldata proof)
        external
        payable
        nonReentrant
    {
        if (msg.value != B_CHALLENGE) revert InvalidBond();

        uint256 nowEpoch = _currentEpoch();

        Window storage w = _window[session_id][epoch];
        if (w.end_epoch == 0 || nowEpoch >= w.end_epoch) revert ChallengeWindowClosed();

        Candidate storage cand = _candidates[session_id][epoch][proof.candidate_id];
        if (cand.submitter == address(0)) revert InvalidCandidate();
        if (cand.evicted) revert CandidateEvicted();
        if (cand.disqualified) revert CandidateDisqualified();

        // Stage 1: Merkle-sum proof verification.
        if (proof.sibling_hashes.length != proof.sibling_sums.length) {
            _slashChallengeBondToSubmitter(cand.submitter, msg.value);
            return;
        }

        bytes32 leafHash = _leafHash(
            block.chainid,
            session_id,
            epoch,
            uint32(proof.interval_index),
            proof.claimed_v,
            proof.sig_ghost,
            proof.sig_shell
        );

        (bytes32 rootHash, uint32 rootSum) = _computeRootFromProof(
            leafHash,
            uint32(proof.claimed_v),
            proof.interval_index,
            proof.sibling_hashes,
            proof.sibling_sums
        );

        if (rootHash != cand.log_root) {
            // Invalid proof (challenger burden): slash B_challenge to submitter.
            _slashChallengeBondToSubmitter(cand.submitter, msg.value);
            return;
        }

        // Stage 2: fraud detection.
        bool fraud = false;
        if (rootSum != cand.su_delivered) {
            fraud = true;
        } else {
            // Fraud iff the committed v_i disagrees with what the heartbeat signatures prove.
            bytes32 hb = _heartbeatDigest(block.chainid, session_id, epoch, proof.interval_index);
            (bytes memory ghost_key, bytes memory shell_key, ) = sessionManager.getSessionKeys(session_id);
            bool g_ok = _verifySessionSig(ghost_key, hb, proof.sig_ghost);
            bool s_ok = _verifySessionSig(shell_key, hb, proof.sig_shell);
            uint8 proven_v = (g_ok && s_ok) ? 1 : 0;
            if (proven_v != proof.claimed_v) {
                fraud = true;
            }
        }

        if (!fraud) {
            _slashChallengeBondToSubmitter(cand.submitter, msg.value);
            return;
        }

        // Successful fraud proof: disqualify candidate, slash receipt bond, reward challenger, burn remainder.
        _disqualifyAndSlashCandidate(session_id, epoch, proof.candidate_id, msg.sender);

        // Return B_challenge to challenger (full).
        _sendValue(msg.sender, msg.value);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Data availability
    // ─────────────────────────────────────────────────────────────────────────────

    function challengeReceiptDA(uint256 session_id, uint256 epoch, uint256 candidate_id)
        external
        payable
        nonReentrant
    {
        if (msg.value != B_DA) revert InvalidBond();

        uint256 nowEpoch = _currentEpoch();

        Window storage w = _window[session_id][epoch];
        if (w.end_epoch == 0 || nowEpoch >= w.end_epoch) revert ChallengeWindowClosed();

        DAChallenge storage da = _da[session_id][epoch];
        if (da.pending) revert DAPending();

        Candidate storage cand = _candidates[session_id][epoch][candidate_id];
        if (cand.submitter == address(0)) revert InvalidCandidate();
        if (cand.evicted) revert CandidateEvicted();
        if (cand.disqualified) revert CandidateDisqualified();
        if (cand.log_published_onchain) revert DAAlreadyPublished();

        da.pending = true;
        da.deadline_epoch = nowEpoch + DA_RESPONSE_WINDOW;
        da.candidate_id = candidate_id;
        da.challenger = msg.sender;
        da.bond = msg.value;

        // Extend finalization freeze.
        if (da.deadline_epoch > w.end_epoch) {
            w.end_epoch = da.deadline_epoch;
        }

        _pendingDAByEpoch[epoch] += 1;
    }

    function publishReceiptLog(uint256 session_id, uint256 epoch, uint256 candidate_id, bytes calldata encoded_log)
        external
        nonReentrant
    {
        uint256 nowEpoch = _currentEpoch();

        DAChallenge storage da = _da[session_id][epoch];
        if (!da.pending || da.candidate_id != candidate_id) revert DANotPending();
        if (nowEpoch >= da.deadline_epoch) revert DAWindowClosed();

        Candidate storage cand = _candidates[session_id][epoch][candidate_id];
        if (cand.submitter == address(0)) revert InvalidCandidate();
        if (cand.evicted) revert CandidateEvicted();
        if (cand.disqualified) revert CandidateDisqualified();

        // Recompute log_root and SU_root from the published log (without verifying signatures).
        (bytes32 rootHash, uint32 rootSum) = _computeRootFromEncodedLog(session_id, epoch, encoded_log);

        if (rootHash != cand.log_root || rootSum != cand.su_delivered) revert InvalidCandidate();

        cand.log_published_onchain = true;

        // Clear DA challenge and pay B_DA to responder.
        da.pending = false;
        _pendingDAByEpoch[epoch] -= 1;

        uint256 payout = da.bond;
        da.bond = 0;
        _sendValue(msg.sender, payout);

        // Restart challenge window (extension) per spec if cap not reached.
        Window storage w = _window[session_id][epoch];
        if (w.extensions_used < MAX_CHALLENGE_EXTENSIONS) {
            w.start_epoch = nowEpoch;
            w.end_epoch = nowEpoch + CHALLENGE_WINDOW;
            w.extensions_used += 1;
        }
    }

    function resolveReceiptDA(uint256 session_id, uint256 epoch, uint256 candidate_id) external nonReentrant {
        uint256 nowEpoch = _currentEpoch();

        DAChallenge storage da = _da[session_id][epoch];
        if (!da.pending || da.candidate_id != candidate_id) revert DANotPending();
        if (nowEpoch < da.deadline_epoch) revert DAWindowClosed();

        // Disqualify + slash receipt bond, pay challenger reward, burn remainder, and return B_DA in full.
        // (The internal helper auto-resolves the DA challenge when disqualifying the challenged candidate.)
        _disqualifyAndSlashCandidate(session_id, epoch, candidate_id, da.challenger);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Finalization
    // ─────────────────────────────────────────────────────────────────────────────

    function finalizeReceipt(uint256 session_id, uint256 epoch) external nonReentrant {
        if (_finalized[session_id][epoch]) revert AlreadyFinalized();

        uint256 nowEpoch = _currentEpoch();

        FinalizationData memory r = _prepareFinalization(session_id, epoch, nowEpoch);

        // Settle rent/escrow.
        sessionManager.settleEpoch(session_id, epoch, r.su_delivered);

        // Record receipt for rewards accounting.
        rewardsManager.recordReceipt(r.receipt_id, epoch, r.ghost_id, r.shell_id, r.su_delivered, r.weight_q);

        // Return receipt bonds to winner + runner-ups.
        _refundCandidateBonds(session_id, epoch);

        _finalized[session_id][epoch] = true;
        _finalReceipts[session_id][epoch] = FinalReceipt({
            receipt_id: r.receipt_id,
            session_id: session_id,
            epoch: epoch,
            log_root: r.log_root,
            su_delivered: r.su_delivered,
            submitter: r.submitter,
            shell_reward_eligible: r.shell_reward_eligible,
            weight_q: r.weight_q
        });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────────

    function _currentEpoch() internal view returns (uint256) {
        if (block.timestamp < GENESIS_TIME) revert PreGenesis();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    function _sendValue(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH_SEND_FAIL");
    }

    function _prepareFinalization(uint256 session_id, uint256 epoch, uint256 nowEpoch)
        internal
        returns (FinalizationData memory r)
    {
        // Condition 1: submission window closed.
        if (nowEpoch < epoch + 1 + SUBMISSION_WINDOW) revert NotFinalizable();

        Window storage w = _window[session_id][epoch];
        // Condition 2: challenge window expired.
        if (w.end_epoch != 0 && nowEpoch < w.end_epoch) revert NotFinalizable();

        // Condition 3: no unresolved DA.
        DAChallenge storage da = _da[session_id][epoch];
        if (da.pending) {
            if (nowEpoch >= da.deadline_epoch) {
                // Must resolve DA timeout before proceeding (may restart window via takeover).
                _disqualifyAndSlashCandidate(session_id, epoch, da.candidate_id, da.challenger);
            } else {
                revert NotFinalizable();
            }
        }

        // Re-check challenge window condition in case resolving DA triggered a restart.
        if (w.end_epoch != 0 && nowEpoch < w.end_epoch) revert NotFinalizable();

        // Select best non-disqualified candidate (candidate_ids list is sorted; disqualified removed).
        uint256 winnerId = 0;
        uint256[] storage ids = _candidateIds[session_id][epoch];
        if (ids.length > 0) {
            winnerId = ids[0];
        }

        bytes32 log_root = bytes32(0);
        uint32 su_delivered = 0;
        address submitter = address(0);
        if (winnerId != 0) {
            Candidate storage winner = _candidates[session_id][epoch][winnerId];
            if (!winner.disqualified && !winner.evicted) {
                log_root = winner.log_root;
                su_delivered = winner.su_delivered;
                submitter = winner.submitter;
            }
        }

        // Validate session billability for this epoch; if invalid, settle as zero.
        SessionStateView memory s = _getSessionByIdView(session_id);
        if (!_isSessionBillableForEpoch(s, epoch)) {
            log_root = bytes32(0);
            su_delivered = 0;
            submitter = address(0);
        }

        bytes32 receipt_id = keccak256(abi.encode(TAG_RECEIPT_ID, block.chainid, address(this), session_id, epoch));

        // Compute weight_q (Q64.64). If SU_delivered = 0, weight_q = 0.
        uint256 weight_q = 0;
        bool shell_reward_eligible = false;
        if (su_delivered > 0 && submitter != address(0)) {
            weight_q = _computeWeightQ64(s, epoch, su_delivered);
            shell_reward_eligible = true; // full eligibility is enforced in RewardsManager per spec
        }

        r = FinalizationData({
            receipt_id: receipt_id,
            ghost_id: s.ghost_id,
            shell_id: s.shell_id,
            log_root: log_root,
            su_delivered: su_delivered,
            submitter: submitter,
            shell_reward_eligible: shell_reward_eligible,
            weight_q: weight_q
        });
    }

    function _refundCandidateBonds(uint256 session_id, uint256 epoch) internal {
        uint256[] storage ids = _candidateIds[session_id][epoch];
        // Return receipt bonds to winner and any non-disqualified, non-evicted runner-ups.
        // (Disqualified bonds were already slashed; evicted were refunded at eviction time.)
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 cid = ids[i];
            Candidate storage c = _candidates[session_id][epoch][cid];
            if (!c.disqualified && !c.evicted && c.bond != 0) {
                uint256 refundBond = c.bond;
                c.bond = 0;
                _sendValue(c.submitter, refundBond);
            }
        }
    }

    function _requiredReceiptBond(uint256 session_id, address caller) internal view returns (uint256) {
        (bytes memory ghost_key, bytes memory shell_key, address submitter) = sessionManager.getSessionKeys(session_id);
        if (caller == submitter) return B_RECEIPT;
        (uint8 g_alg, bytes memory g_pk) = abi.decode(ghost_key, (uint8, bytes));
        if (g_alg == 1) {
            (bool ok, address g_addr) = _tryK1AddressFromUncompressedPubkey(g_pk);
            if (ok && caller == g_addr) return B_RECEIPT;
        }
        (uint8 s_alg, bytes memory s_pk) = abi.decode(shell_key, (uint8, bytes));
        if (s_alg == 1) {
            (bool ok, address s_addr) = _tryK1AddressFromUncompressedPubkey(s_pk);
            if (ok && caller == s_addr) return B_RECEIPT;
        }
        return B_RECEIPT_3P;
    }

    function _isBetter(uint32 suA, uint256 idA, uint32 suB, uint256 idB) internal pure returns (bool) {
        if (suA > suB) return true;
        if (suA < suB) return false;
        return idA < idB;
    }

    function _findInsertPosition(uint256 session_id, uint256 epoch, uint32 su, uint256 id)
        internal
        view
        returns (uint256)
    {
        uint256[] storage ids = _candidateIds[session_id][epoch];
        for (uint256 i = 0; i < ids.length; i++) {
            Candidate storage c = _candidates[session_id][epoch][ids[i]];
            if (_isBetter(su, id, c.su_delivered, ids[i])) {
                return i;
            }
        }
        return ids.length;
    }

    function _evictCandidate(uint256 session_id, uint256 epoch, uint256 candidate_id) internal {
        Candidate storage c = _candidates[session_id][epoch][candidate_id];
        if (c.submitter == address(0) || c.evicted) return;
        c.evicted = true;

        // If this candidate is currently DA-challenged, auto-resolve (moot) and return B_DA.
        DAChallenge storage da = _da[session_id][epoch];
        if (da.pending && da.candidate_id == candidate_id) {
            da.pending = false;
            _pendingDAByEpoch[epoch] -= 1;
            uint256 refund = da.bond;
            da.bond = 0;
            _sendValue(da.challenger, refund);
        }

        // Return receipt bond immediately.
        uint256 refundBond = c.bond;
        c.bond = 0;
        _sendValue(c.submitter, refundBond);
    }

    function _removeCandidateId(uint256 session_id, uint256 epoch, uint256 candidate_id) internal returns (bool wasBest) {
        uint256[] storage ids = _candidateIds[session_id][epoch];
        if (ids.length == 0) return false;
        if (ids[0] == candidate_id) wasBest = true;
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] == candidate_id) {
                for (uint256 j = i; j + 1 < ids.length; j++) {
                    ids[j] = ids[j + 1];
                }
                ids.pop();
                break;
            }
        }
    }

    function _slashChallengeBondToSubmitter(address submitter, uint256 amount) internal {
        _sendValue(submitter, amount);
    }

    function _disqualifyAndSlashCandidate(uint256 session_id, uint256 epoch, uint256 candidate_id, address challenger)
        internal
    {
        Candidate storage c = _candidates[session_id][epoch][candidate_id];
        if (c.submitter == address(0) || c.evicted || c.disqualified) return;

        bool wasBest = _removeCandidateId(session_id, epoch, candidate_id);
        c.disqualified = true;

        // If DA pending on this candidate, auto-resolve and return B_DA to DA challenger.
        DAChallenge storage da = _da[session_id][epoch];
        if (da.pending && da.candidate_id == candidate_id) {
            da.pending = false;
            _pendingDAByEpoch[epoch] -= 1;
            uint256 refund = da.bond;
            da.bond = 0;
            _sendValue(da.challenger, refund);
        }

        // Slash receipt bond.
        uint256 slashed = c.bond;
        c.bond = 0;
        if (slashed != 0) {
            uint256 reward = Math.mulDiv(slashed, bps_challenger_reward, 10_000);
            uint256 burnAmt = slashed - reward;
            _sendValue(challenger, reward);
            _sendValue(burn_address, burnAmt);
        }

        // Runner-up takeover: if best changed due to disqualification, restart window (extension) if cap not reached.
        if (wasBest) {
            uint256[] storage ids = _candidateIds[session_id][epoch];
            if (ids.length > 0) {
                Window storage w = _window[session_id][epoch];
                uint256 nowEpoch = _currentEpoch();
                if (w.extensions_used < MAX_CHALLENGE_EXTENSIONS) {
                    w.start_epoch = nowEpoch;
                    w.end_epoch = nowEpoch + CHALLENGE_WINDOW;
                    w.extensions_used += 1;
                }
            }
        }
    }

    function _heartbeatDigest(uint256 chain_id, uint256 session_id, uint256 epoch, uint256 interval_index)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_HEARTBEAT, chain_id, session_id, epoch, interval_index));
    }

    function _leafHash(
        uint256 chain_id,
        uint256 session_id,
        uint256 epoch,
        uint32 interval_index,
        uint8 v_i,
        bytes memory sig_ghost,
        bytes memory sig_shell
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TAG_LOG_LEAF,
                chain_id,
                session_id,
                epoch,
                interval_index,
                v_i,
                keccak256(sig_ghost),
                keccak256(sig_shell)
            )
        );
    }

    function _nodeHash(bytes32 hL, bytes32 hR, uint32 sL, uint32 sR) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_LOG_NODE, hL, hR, sL, sR));
    }

    function _computeRootFromProof(
        bytes32 leafHash,
        uint32 leafSum,
        uint32 interval_index,
        bytes32[] calldata sibling_hashes,
        uint32[] calldata sibling_sums
    ) internal pure returns (bytes32 rootHash, uint32 rootSum) {
        bytes32 h = leafHash;
        uint32 s = leafSum;
        uint32 idx = interval_index;

        for (uint256 i = 0; i < sibling_hashes.length; i++) {
            bytes32 sibH = sibling_hashes[i];
            uint32 sibS = sibling_sums[i];
            if ((idx & 1) == 0) {
                h = _nodeHash(h, sibH, s, sibS);
                s = s + sibS;
            } else {
                h = _nodeHash(sibH, h, sibS, s);
                s = sibS + s;
            }
            idx >>= 1;
        }

        return (h, s);
    }

    function _computeRootFromEncodedLog(uint256 session_id, uint256 epoch, bytes calldata encoded_log)
        internal
        view
        returns (bytes32 rootHash, uint32 rootSum)
    {
        (bytes memory ghost_key, bytes memory shell_key, ) = sessionManager.getSessionKeys(session_id);
        uint256 sigLenG = _sigLen(ghost_key);
        uint256 sigLenS = _sigLen(shell_key);

        uint256 bitmapLen = (N + 7) / 8;
        if (encoded_log.length < bitmapLen) revert InvalidCandidate();

        bytes calldata bitmap = encoded_log[:bitmapLen];
        bytes calldata sigPairs = encoded_log[bitmapLen:];

        uint256 ones = 0;
        // Count set bits for indices [0..N-1] (LSB-first within each byte).
        for (uint256 i = 0; i < bitmapLen; i++) {
            uint8 b = uint8(bitmap[i]);
            // Mask out bits beyond N in last byte.
            if (i == bitmapLen - 1) {
                uint256 validBits = N - i * 8;
                if (validBits < 8) {
                    uint8 mask = uint8((1 << validBits) - 1);
                    b &= mask;
                }
            }
            ones += _popcount8(b);
        }

        uint256 expectedSigLen = ones * (sigLenG + sigLenS);
        if (sigPairs.length != expectedSigLen) revert InvalidCandidate();

        // Streamed Merkle-sum construction over N_PAD leaves.
        // Stack size is log2(N_PAD)+1, bounded by 256 for any reasonable N_PAD.
        uint256 maxH = _log2(N_PAD) + 1;
        bytes32[] memory hStack = new bytes32[](maxH);
        uint32[] memory sStack = new uint32[](maxH);
        bool[] memory has = new bool[](maxH);

        uint256 sigOffset = 0;
        for (uint256 i = 0; i < N_PAD; i++) {
            uint8 v = 0;
            bytes memory sigG = "";
            bytes memory sigS = "";

            if (i < N) {
                uint8 bit = (uint8(bitmap[i / 8]) >> (i % 8)) & 1;
                if (bit == 1) {
                    v = 1;
                    sigG = sigPairs[sigOffset: sigOffset + sigLenG];
                    sigOffset += sigLenG;
                    sigS = sigPairs[sigOffset: sigOffset + sigLenS];
                    sigOffset += sigLenS;
                }
            }

            bytes32 leafH = _leafHash(block.chainid, session_id, epoch, uint32(i), v, sigG, sigS);
            uint32 leafS = uint32(v);

            bytes32 curH = leafH;
            uint32 curS = leafS;
            uint256 level = 0;
            while (true) {
                if (!has[level]) {
                    hStack[level] = curH;
                    sStack[level] = curS;
                    has[level] = true;
                    break;
                }
                // Combine: left = stack, right = current
                curH = _nodeHash(hStack[level], curH, sStack[level], curS);
                curS = sStack[level] + curS;
                has[level] = false;
                level++;
            }
        }

        // Root should be at the highest occupied level.
        for (uint256 level = maxH; level > 0; level--) {
            if (has[level - 1]) {
                rootHash = hStack[level - 1];
                rootSum = sStack[level - 1];
                break;
            }
        }
    }

    function _sigLen(bytes memory session_key) internal pure returns (uint256) {
        (uint8 sig_alg, ) = abi.decode(session_key, (uint8, bytes));
        if (sig_alg == 1) return 65; // K1: (r,s,v)
        if (sig_alg == 2) return 64; // R1: (r,s) fixed-length
        revert UnsupportedSigAlg(sig_alg);
    }

    function _verifySessionSig(bytes memory session_key, bytes32 digest, bytes memory sig) internal pure returns (bool) {
        (uint8 sig_alg, bytes memory pk) = abi.decode(session_key, (uint8, bytes));
        if (sig_alg != 1) revert UnsupportedSigAlg(sig_alg);
        (bool ok, address expected) = _tryK1AddressFromUncompressedPubkey(pk);
        if (!ok) return false;
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        return err == ECDSA.RecoverError.NoError && recovered == expected;
    }

    function _tryK1AddressFromUncompressedPubkey(bytes memory pk) internal pure returns (bool ok, address addr) {
        // Spec expects uncompressed 65-byte secp256k1 pubkeys: 0x04 || X(32) || Y(32).
        if (pk.length != 65) return (false, address(0));
        if (pk[0] != 0x04) return (false, address(0));

        bytes32 h;
        // Hash the 64-byte X||Y portion (skip leading 0x04).
        assembly ("memory-safe") {
            h := keccak256(add(pk, 0x21), 64)
        }

        addr = address(uint160(uint256(h)));
        ok = true;
    }

    function _popcount8(uint8 x) internal pure returns (uint8) {
        // Hacker's Delight popcount for 8-bit value.
        x = x - ((x >> 1) & 0x55);
        x = (x & 0x33) + ((x >> 2) & 0x33);
        return (((x + (x >> 4)) & 0x0F));
    }

    function _log2(uint256 x) internal pure returns (uint256 r) {
        // x > 0, returns floor(log2(x))
        while (x > 1) {
            x >>= 1;
            r++;
        }
    }

    function _getSessionByIdView(uint256 session_id) internal view returns (SessionStateView memory s) {
        (bool ok, bytes memory data) =
            address(sessionManager).staticcall(abi.encodeWithSelector(sessionManager.getSessionById.selector, session_id));
        require(ok, "SESSION_CALL_FAIL");
        s = abi.decode(data, (SessionStateView));
    }

    function _isSessionBillableForEpoch(SessionStateView memory s, uint256 epoch) internal view returns (bool) {
        // (1) session_start_epoch <= epoch
        if (s.session_start_epoch > epoch) return false;
        // (2) epoch < session_end_epoch (if ended)
        if (s.end_epoch != 0 && epoch >= s.end_epoch) return false;
        // (3) epoch < effective expiry (using stored tenure limit)
        if (epoch >= s.residency_start_epoch_snapshot + s.residency_tenure_limit_epochs) return false;
        // (4) lease valid at time of service (best-effort: uses stored lease_expiry_epoch)
        if (epoch >= s.lease_expiry_epoch) return false;
        // (5) not staging / pending migration
        if (s.staging || s.pending_migration) return false;
        return true;
    }

    function _computeWeightQ64(SessionStateView memory s, uint256 epoch, uint32 su_delivered)
        internal
        view
        returns (uint256)
    {
        // SU in Q64.64
        uint256 su_q = uint256(su_delivered) << 64;

        // Passport multiplier
        uint256 w_passport_q = Q64;
        if (s.passport_bonus_applies && B_PASSPORT_Q != 0) {
            w_passport_q = Q64 + uint256(B_PASSPORT_Q);
        }

        // Dwell decay
        uint256 c = (epoch - s.residency_start_epoch_snapshot) + 1; // 1-indexed epoch-of-residency
        uint256 k = 0;
        if (c > 1) {
            k = (c - 1) / D;
            if (k > 63) k = 63;
        }
        uint256 w_dwell_q = Q64 >> k;

        uint256 step2 = _mulQ64(su_q, w_passport_q);
        return _mulQ64(step2, w_dwell_q);
    }

    function _mulQ64(uint256 a, uint256 b) internal pure returns (uint256) {
        // floor(a*b / Q)
        return (a * b) / Q64;
    }
}
