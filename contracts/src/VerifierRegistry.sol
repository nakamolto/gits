// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifierRegistry} from "./interfaces/IVerifierRegistry.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title VerifierRegistry
/// @notice Verifier staking, active-set computation, measurement allowlist, and equivocation proofs.
/// @dev Spec: GITS Part 3, Section 14.7 (VerifierRegistry).
contract VerifierRegistry is IVerifierRegistry {
    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────────

    error PreGenesis();
    error InvalidEpochLen();
    error InvalidBps();
    error InvalidAsset();
    error AmountZero();
    error AlreadyRegistered();
    error NotRegistered();
    error Unauthorized();
    error PendingDecreaseExists();
    error NoPendingDecrease();
    error UnbondNotReady(uint256 current_epoch, uint256 available_epoch);
    error DecreaseTooLarge(uint256 amount, uint256 active);
    error SlashTooLarge(uint256 amount, uint256 total);

    error InvalidTierClass();
    error InvalidNonce(uint64 expected, uint64 provided);
    error QuorumNotMet(uint256 required, uint256 provided);
    error SignersNotSorted();
    error SignerNotActive(address signer);

    error InvalidACPayload();
    error ShellIdMismatch();
    error ValidityNotOverlapping();
    error DigestsEqual();
    error SignerMismatch();
    error NoStakeToSlash();

    // ─────────────────────────────────────────────────────────────────────────────
    // Constants / Immutables
    // ─────────────────────────────────────────────────────────────────────────────

    bytes32 internal constant TAG_ALLOW_MEASUREMENT = keccak256(bytes("GITS_ALLOW_MEASUREMENT"));
    bytes32 internal constant TAG_REVOKE_MEASUREMENT = keccak256(bytes("GITS_REVOKE_MEASUREMENT"));
    bytes32 internal constant TAG_AC = keccak256(bytes("GITS_AC"));
    bytes32 internal constant REASON_EQUIVOCATION = keccak256(bytes("GITS_VERIFIER_EQUIVOCATION"));

    uint256 public immutable K_V;
    uint256 public immutable K_V_THRESHOLD;
    uint256 public immutable T_STAKE_ACTIVATION;
    uint256 public immutable T_STAKE_UNBOND;
    uint256 public immutable BPS_VERIFIER_CHALLENGER_REWARD;
    address public immutable PROTOCOL_BURN_ADDRESS;
    address public immutable ASSET_VERIFIER_STAKE;
    address public immutable SHELL_REGISTRY;
    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    // ─────────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────────

    struct StakeTranche {
        uint256 amount;
        uint256 activationEpoch; // inclusive
    }

    struct ACFields {
        bytes32 shell_id;
        uint8 tee_type;
        bytes32 measurement_hash;
        bytes32 tcb_min;
        uint256 valid_from;
        uint256 valid_to;
        uint8 assurance_tier;
        bytes32 evidence_hash;
    }

    struct VerifierState {
        uint256 totalStake; // activated + pendingDecrease + unactivated
        uint256 activatedStake; // score-bearing stake (synced up to activationCursor)
        uint256 pendingDecrease;
        uint64 pendingAvailableEpoch;
        uint256 activationCursor;
        StakeTranche[] tranches;
    }

    address[] private _verifiers;
    mapping(address => uint256) private _verifierIndexPlusOne;
    mapping(address => VerifierState) private _verifierState;

    // tier_class -> measurement_hash -> allowed
    mapping(uint8 => mapping(bytes32 => bool)) private _measurementAllowed;

    uint64 private _measurementNonce;

    // ─────────────────────────────────────────────────────────────────────────────
    // Construction
    // ─────────────────────────────────────────────────────────────────────────────

    constructor(
        uint256 k_v,
        uint256 k_v_threshold,
        uint256 t_stake_activation,
        uint256 t_stake_unbond,
        uint256 bps_verifier_challenger_reward,
        address protocol_burn_address,
        address asset_verifier_stake,
        address shell_registry,
        uint256 genesis_time,
        uint256 epoch_len
    ) {
        if (epoch_len == 0) revert InvalidEpochLen();
        if (bps_verifier_challenger_reward > 10_000) revert InvalidBps();

        K_V = k_v;
        K_V_THRESHOLD = k_v_threshold;
        T_STAKE_ACTIVATION = t_stake_activation;
        T_STAKE_UNBOND = t_stake_unbond;
        BPS_VERIFIER_CHALLENGER_REWARD = bps_verifier_challenger_reward;
        PROTOCOL_BURN_ADDRESS = protocol_burn_address;
        ASSET_VERIFIER_STAKE = asset_verifier_stake;
        SHELL_REGISTRY = shell_registry;
        GENESIS_TIME = genesis_time;
        EPOCH_LEN = epoch_len;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Epoch Clock
    // ─────────────────────────────────────────────────────────────────────────────

    function _assertAfterGenesis() internal view {
        if (block.timestamp < GENESIS_TIME) revert PreGenesis();
    }

    function _currentEpoch() internal view returns (uint256) {
        _assertAfterGenesis();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Registration Helpers
    // ─────────────────────────────────────────────────────────────────────────────

    function _isRegistered(address verifier) internal view returns (bool) {
        return _verifierIndexPlusOne[verifier] != 0;
    }

    function _requireRegistered(address verifier) internal view {
        if (!_isRegistered(verifier)) revert NotRegistered();
    }

    function _unregisterVerifier(address verifier) internal {
        uint256 idxPlusOne = _verifierIndexPlusOne[verifier];
        if (idxPlusOne == 0) return;

        uint256 idx = idxPlusOne - 1;
        uint256 lastIdx = _verifiers.length - 1;
        if (idx != lastIdx) {
            address moved = _verifiers[lastIdx];
            _verifiers[idx] = moved;
            _verifierIndexPlusOne[moved] = idx + 1;
        }
        _verifiers.pop();
        _verifierIndexPlusOne[verifier] = 0;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Stake Activation (lazy)
    // ─────────────────────────────────────────────────────────────────────────────

    function _syncActivation(address verifier) internal {
        VerifierState storage st = _verifierState[verifier];
        uint256 epoch = _currentEpoch();

        uint256 i = st.activationCursor;
        uint256 len = st.tranches.length;
        while (i < len) {
            StakeTranche storage tr = st.tranches[i];
            // tr.amount may be zeroed by prior activation or slashing.
            if (tr.amount == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }
            if (tr.activationEpoch > epoch) break;

            st.activatedStake += tr.amount;
            delete st.tranches[i];
            unchecked {
                ++i;
            }
        }

        st.activationCursor = i;
    }

    function _activatedStakeNow(address verifier) internal view returns (uint256) {
        VerifierState storage st = _verifierState[verifier];
        uint256 epoch = _currentEpoch();

        uint256 activated = st.activatedStake;
        uint256 i = st.activationCursor;
        uint256 len = st.tranches.length;
        while (i < len) {
            StakeTranche storage tr = st.tranches[i];
            if (tr.amount == 0) {
                unchecked {
                    ++i;
                }
                continue;
            }
            if (tr.activationEpoch > epoch) break;
            activated += tr.amount;
            unchecked {
                ++i;
            }
        }
        return activated;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Staking
    // ─────────────────────────────────────────────────────────────────────────────

    function registerVerifier(address asset, uint256 amount) external {
        _assertAfterGenesis();
        if (asset != ASSET_VERIFIER_STAKE) revert InvalidAsset();
        if (amount == 0) revert AmountZero();
        if (_isRegistered(msg.sender)) revert AlreadyRegistered();

        uint256 epoch = _currentEpoch();
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);

        _verifierIndexPlusOne[msg.sender] = _verifiers.length + 1;
        _verifiers.push(msg.sender);

        VerifierState storage st = _verifierState[msg.sender];
        st.totalStake = amount;
        st.tranches.push(StakeTranche({amount: amount, activationEpoch: epoch + T_STAKE_ACTIVATION}));

        emit VerifierRegistered(msg.sender, asset, amount);
    }

    function increaseStake(address asset, uint256 amount) external {
        _assertAfterGenesis();
        if (asset != ASSET_VERIFIER_STAKE) revert InvalidAsset();
        if (amount == 0) revert AmountZero();
        _requireRegistered(msg.sender);

        uint256 epoch = _currentEpoch();
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);

        VerifierState storage st = _verifierState[msg.sender];
        st.totalStake += amount;
        st.tranches.push(StakeTranche({amount: amount, activationEpoch: epoch + T_STAKE_ACTIVATION}));

        emit StakeIncreased(msg.sender, asset, amount);
    }

    function beginDecreaseStake(address asset, uint256 amount) external {
        _assertAfterGenesis();
        if (asset != ASSET_VERIFIER_STAKE) revert InvalidAsset();
        if (amount == 0) revert AmountZero();
        _requireRegistered(msg.sender);

        VerifierState storage st = _verifierState[msg.sender];
        if (st.pendingDecrease != 0) revert PendingDecreaseExists();

        uint256 epoch = _currentEpoch();
        _syncActivation(msg.sender);

        uint256 active = st.activatedStake;
        if (amount > active) revert DecreaseTooLarge(amount, active);

        // Immediate stakeScore reduction: removed from active stake as soon as unbonding begins.
        st.activatedStake = active - amount;
        st.pendingDecrease = amount;
        st.pendingAvailableEpoch = uint64(epoch + T_STAKE_UNBOND);

        emit StakeDecreaseBegun(msg.sender, asset, amount, epoch + T_STAKE_UNBOND);
    }

    function withdrawDecreasedStake(address asset) external {
        _assertAfterGenesis();
        if (asset != ASSET_VERIFIER_STAKE) revert InvalidAsset();
        _requireRegistered(msg.sender);

        VerifierState storage st = _verifierState[msg.sender];
        uint256 amount = st.pendingDecrease;
        if (amount == 0) revert NoPendingDecrease();

        uint256 epoch = _currentEpoch();
        uint256 availableEpoch = uint256(st.pendingAvailableEpoch);
        if (epoch < availableEpoch) revert UnbondNotReady(epoch, availableEpoch);

        st.pendingDecrease = 0;
        st.pendingAvailableEpoch = 0;
        st.totalStake -= amount;

        IERC20(asset).safeTransfer(msg.sender, amount);
        emit StakeWithdrawn(msg.sender, asset, amount);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Slashing
    // ─────────────────────────────────────────────────────────────────────────────

    function slashVerifier(address verifier, address asset, uint256 amount, bytes32 reason) external {
        _assertAfterGenesis();
        if (msg.sender != SHELL_REGISTRY) revert Unauthorized();
        if (asset != ASSET_VERIFIER_STAKE) revert InvalidAsset();
        if (amount == 0) revert AmountZero();
        _requireRegistered(verifier);

        _slashStake(verifier, amount);
        IERC20(asset).safeTransfer(PROTOCOL_BURN_ADDRESS, amount);

        emit VerifierSlashed(verifier, asset, amount, reason);
    }

    function _slashStake(address verifier, uint256 amount) internal {
        VerifierState storage st = _verifierState[verifier];
        if (amount > st.totalStake) revert SlashTooLarge(amount, st.totalStake);

        // Bring activated stake up to date first; then slash in priority order:
        // pendingDecrease → activated → unactivated (LIFO).
        _syncActivation(verifier);

        uint256 remaining = amount;

        // 1) pendingDecrease
        uint256 pd = st.pendingDecrease;
        if (pd != 0) {
            uint256 slashPd = remaining < pd ? remaining : pd;
            st.pendingDecrease = pd - slashPd;
            if (st.pendingDecrease == 0) st.pendingAvailableEpoch = 0;
            st.totalStake -= slashPd;
            remaining -= slashPd;
        }

        // 2) activated (score-bearing)
        if (remaining != 0) {
            uint256 act = st.activatedStake;
            uint256 slashAct = remaining < act ? remaining : act;
            st.activatedStake = act - slashAct;
            st.totalStake -= slashAct;
            remaining -= slashAct;
        }

        // 3) unactivated tranches (LIFO)
        if (remaining != 0) {
            uint256 i = st.tranches.length;
            while (remaining != 0 && i != 0) {
                unchecked {
                    --i;
                }
                StakeTranche storage tr = st.tranches[i];
                uint256 trAmt = tr.amount;
                if (trAmt == 0) continue;

                uint256 slashTr = remaining < trAmt ? remaining : trAmt;
                tr.amount = trAmt - slashTr;
                if (tr.amount == 0) delete st.tranches[i];

                st.totalStake -= slashTr;
                remaining -= slashTr;
            }
        }

        // amount <= totalStake precondition ensures we can always cover.
        assert(remaining == 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Measurement Allowlist
    // ─────────────────────────────────────────────────────────────────────────────

    function allowMeasurement(bytes32 measurement_hash, uint8 tier_class, uint64 nonce, bytes[] calldata sigs_verifiers)
        external
    {
        _assertAfterGenesis();
        if (tier_class > 1) revert InvalidTierClass();

        uint64 expected = _measurementNonce;
        if (nonce != expected) revert InvalidNonce(expected, nonce);

        bytes32 digest =
            keccak256(abi.encode(TAG_ALLOW_MEASUREMENT, block.chainid, address(this), measurement_hash, tier_class, nonce));
        _checkQuorum(digest, sigs_verifiers, _kVSupermajority());

        _measurementNonce = expected + 1;
        _measurementAllowed[tier_class][measurement_hash] = true;
        emit MeasurementAllowed(measurement_hash, tier_class);
    }

    function revokeMeasurement(bytes32 measurement_hash, uint64 nonce, bytes[] calldata sigs_verifiers) external {
        _assertAfterGenesis();
        uint64 expected = _measurementNonce;
        if (nonce != expected) revert InvalidNonce(expected, nonce);

        bytes32 digest =
            keccak256(abi.encode(TAG_REVOKE_MEASUREMENT, block.chainid, address(this), measurement_hash, nonce));
        _checkQuorum(digest, sigs_verifiers, K_V_THRESHOLD);

        _measurementNonce = expected + 1;

        // revokeMeasurement has no tier_class parameter, so it revokes the measurement for all tiers.
        _measurementAllowed[0][measurement_hash] = false;
        _measurementAllowed[1][measurement_hash] = false;

        emit MeasurementRevoked(measurement_hash);
    }

    function _kVSupermajority() internal view returns (uint256) {
        // ceil(2*K/3) for integers: (2*K + 2) / 3
        return (2 * K_V + 2) / 3;
    }

    function _checkQuorum(bytes32 digest, bytes[] calldata sigs, uint256 required) internal view {
        if (sigs.length < required) revert QuorumNotMet(required, sigs.length);

        address[] memory active = _computeActiveSet();

        address prevSigner = address(0);
        for (uint256 i = 0; i < sigs.length; ++i) {
            address signer = ECDSA.recover(digest, sigs[i]);
            if (signer <= prevSigner) revert SignersNotSorted();
            prevSigner = signer;
            if (!_isInSet(active, signer)) revert SignerNotActive(signer);
        }
    }

    function _isInSet(address[] memory set, address a) internal pure returns (bool) {
        for (uint256 i = 0; i < set.length; ++i) {
            if (set[i] == a) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Equivocation Proof
    // ─────────────────────────────────────────────────────────────────────────────

    function proveVerifierEquivocation(
        address verifier,
        bytes32 shell_id,
        bytes calldata ac_payload_a,
        bytes calldata sig_a,
        bytes calldata ac_payload_b,
        bytes calldata sig_b
    ) external {
        _assertAfterGenesis();
        _requireRegistered(verifier);

        // Use a scoped block to keep the equivocation verification stack-light.
        {
            ACFields memory a = _decodeACPayload(ac_payload_a);
            ACFields memory b = _decodeACPayload(ac_payload_b);

            if (a.shell_id != shell_id || b.shell_id != shell_id || a.shell_id != b.shell_id) revert ShellIdMismatch();

            bytes32 digest_a = _acDigest(a);
            bytes32 digest_b = _acDigest(b);

            if (digest_a == digest_b) revert DigestsEqual();

            // Overlap check: valid_from_a < valid_to_b AND valid_from_b < valid_to_a
            if (!(a.valid_from < b.valid_to && b.valid_from < a.valid_to)) revert ValidityNotOverlapping();

            if (ECDSA.recover(digest_a, sig_a) != verifier) revert SignerMismatch();
            if (ECDSA.recover(digest_b, sig_b) != verifier) revert SignerMismatch();
        }

        uint256 total = _verifierState[verifier].totalStake;
        if (total == 0) revert NoStakeToSlash();

        uint256 reward = (total * BPS_VERIFIER_CHALLENGER_REWARD) / 10_000;

        // Effects first.
        delete _verifierState[verifier];
        _unregisterVerifier(verifier);

        // Interactions.
        IERC20(ASSET_VERIFIER_STAKE).safeTransfer(msg.sender, reward);
        IERC20(ASSET_VERIFIER_STAKE).safeTransfer(PROTOCOL_BURN_ADDRESS, total - reward);

        emit VerifierSlashed(verifier, ASSET_VERIFIER_STAKE, total, REASON_EQUIVOCATION);
    }

    function _decodeACPayload(bytes calldata payload)
        internal pure returns (ACFields memory f)
    {
        // Expected: abi.encode(shell_id, tee_type, measurement_hash, tcb_min, valid_from, valid_to, assurance_tier, evidence_hash)
        if (payload.length != 32 * 8) revert InvalidACPayload();
        (f.shell_id, f.tee_type, f.measurement_hash, f.tcb_min, f.valid_from, f.valid_to, f.assurance_tier, f.evidence_hash) =
            abi.decode(payload, (bytes32, uint8, bytes32, bytes32, uint256, uint256, uint8, bytes32));
    }

    function _acDigest(ACFields memory f) internal view returns (bytes32) {
        // Spec (Section 14.1): keccak256(abi.encode(TAG_HASH, chain_id, shell_registry_address, ...fields...))
        return keccak256(
            abi.encode(
                TAG_AC,
                block.chainid,
                SHELL_REGISTRY,
                f.shell_id,
                f.tee_type,
                f.measurement_hash,
                f.tcb_min,
                f.valid_from,
                f.valid_to,
                f.assurance_tier,
                f.evidence_hash
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────────────

    function isActiveVerifier(address verifier) external view returns (bool) {
        _assertAfterGenesis();
        if (!_isRegistered(verifier)) return false;

        address[] memory active = _computeActiveSet();
        return _isInSet(active, verifier);
    }

    function stakeScore(address verifier) external view returns (uint256) {
        _assertAfterGenesis();
        _requireRegistered(verifier);
        return activeStake(verifier, ASSET_VERIFIER_STAKE);
    }

    function activeStake(address verifier, address asset) public view returns (uint256) {
        _assertAfterGenesis();
        _requireRegistered(verifier);
        if (asset != ASSET_VERIFIER_STAKE) return 0;
        return _activatedStakeNow(verifier);
    }

    function isMeasurementAllowed(bytes32 measurement_hash, uint8 tier_class) external view returns (bool) {
        _assertAfterGenesis();
        return _measurementAllowed[tier_class][measurement_hash];
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Active Set Computation (Top K_V)
    // ─────────────────────────────────────────────────────────────────────────────

    function _computeActiveSet() internal view returns (address[] memory) {
        uint256 n = _verifiers.length;
        uint256 k = K_V;
        if (k > n) k = n;

        address[] memory top = new address[](k);
        uint256[] memory scores = new uint256[](k);
        uint256 count = 0;

        for (uint256 i = 0; i < n; ++i) {
            address v = _verifiers[i];
            uint256 s = _activatedStakeNow(v);

            if (count < k) {
                top[count] = v;
                scores[count] = s;
                unchecked {
                    ++count;
                }
                _bubbleUp(top, scores, count - 1);
                continue;
            }

            if (k == 0) continue;

            // Replace worst if current is better.
            if (_better(v, s, top[k - 1], scores[k - 1])) {
                top[k - 1] = v;
                scores[k - 1] = s;
                _bubbleUp(top, scores, k - 1);
            }
        }

        return top;
    }

    function _bubbleUp(address[] memory addrs, uint256[] memory scores, uint256 idx) internal pure {
        while (idx > 0) {
            uint256 prev = idx - 1;
            if (_better(addrs[idx], scores[idx], addrs[prev], scores[prev])) {
                (addrs[idx], addrs[prev]) = (addrs[prev], addrs[idx]);
                (scores[idx], scores[prev]) = (scores[prev], scores[idx]);
                idx = prev;
            } else {
                break;
            }
        }
    }

    function _better(address a, uint256 scoreA, address b, uint256 scoreB) internal pure returns (bool) {
        if (scoreA != scoreB) return scoreA > scoreB;
        return a < b;
    }
}
