// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IShellRegistry} from "./interfaces/IShellRegistry.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IVerifierRegistry} from "./interfaces/IVerifierRegistry.sol";
import {ShellRecord, BondStatus} from "./types/GITSTypes.sol";

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

/// @title ShellRegistry
/// @notice Shell identity, bonds, and Attestation Certificates (GITS Part 3, Section 14.1).
contract ShellRegistry is IShellRegistry {
    using SafeERC20 for IERC20;

    // ─── Tags (domain separation) ────────────────────────────────────────────

    bytes32 internal constant TAG_SHELL_ID = keccak256(bytes("GITS_SHELL_ID"));
    bytes32 internal constant TAG_SHELL_REGISTER = keccak256(bytes("GITS_SHELL_REGISTER"));
    bytes32 internal constant TAG_AC = keccak256(bytes("GITS_AC"));
    bytes32 internal constant TAG_SHELL_KEY_PROPOSE = keccak256(bytes("GITS_SHELL_KEY_PROPOSE"));

    // ─── Signature Algorithms ───────────────────────────────────────────────

    uint8 internal constant SIGALG_K1 = 1;
    uint8 internal constant SIGALG_R1 = 2;

    // ─── Deployment Constants / Config ──────────────────────────────────────

    uint256 public immutable GENESIS_TIME;
    uint256 public immutable EPOCH_LEN;

    uint256 public immutable T_SHELL_KEY_DELAY; // epochs
    uint256 public immutable T_UNBOND_SHELL; // epochs
    uint256 public immutable T_UNBOND_SAFEHAVEN; // epochs
    uint256 public immutable TTL_AC; // seconds

    uint256 public immutable K_V_THRESHOLD;
    uint256 public immutable K_V_MAX;
    uint256 public immutable F_CERT;

    uint256 public immutable B_HOST_MIN;
    uint256 public immutable B_SAFEHAVEN_MIN;

    uint256 public immutable BPS_SH_CHALLENGER_REWARD;

    /// @dev Bitmask feature flag: algorithm is supported iff (SUPPORTED_SIG_ALGS & (1 << sig_alg)) != 0.
    uint256 public immutable SUPPORTED_SIG_ALGS;

    address public immutable PROTOCOL_BURN_ADDRESS;
    IERC20 public immutable ASSET_VERIFIER_STAKE;

    ISessionManager public immutable SESSION_MANAGER;
    IVerifierRegistry public immutable VERIFIER_REGISTRY;
    address public immutable RECEIPT_MANAGER;

    // ─── Allow Lists ─────────────────────────────────────────────────────────

    mapping(address => bool) public bondAssets;
    mapping(uint8 => bool) public supportedTeeTypes;

    // ─── Core State ─────────────────────────────────────────────────────────

    mapping(bytes32 => ShellRecord) private _shells;
    mapping(bytes32 => bool) private _registered;

    /// @notice Per-registry nonce incremented on each successful registration (anti-replay).
    uint64 public registry_nonce;

    /// @notice Per-shell nonce used for identity key proposal digests.
    mapping(bytes32 => uint64) public shell_key_nonce;

    // ─── Key Proposals (timelocked) ─────────────────────────────────────────

    struct KeyProposal {
        bytes proposed_key;
        uint256 proposed_at_epoch;
        bool pending;
    }

    mapping(bytes32 => KeyProposal) private _pendingIdentity;
    mapping(bytes32 => KeyProposal) private _pendingOfferSigner;
    mapping(bytes32 => KeyProposal) private _pendingRecovery;

    // ─── Bonds / Unbonding ──────────────────────────────────────────────────

    mapping(bytes32 => uint256) private _pendingUnbondAmount;

    mapping(bytes32 => bool) private _shUnbonding;
    mapping(bytes32 => uint256) private _shUnbondEndEpoch;
    mapping(bytes32 => uint256) private _shUnbondAmount;

    // ─── Certificates ───────────────────────────────────────────────────────

    struct CertState {
        uint8 tee_type;
        bytes32 measurement_hash;
        bytes32 tcb_min;
        uint256 valid_from;
        uint256 valid_to;
        uint8 assurance_tier;
        bytes32 evidence_hash;
    }

    mapping(bytes32 => CertState) private _certs;

    struct ACPayload {
        bytes32 shell_id;
        uint8 tee_type;
        bytes32 measurement_hash;
        bytes32 tcb_min;
        uint256 valid_from;
        uint256 valid_to;
        uint8 assurance_tier;
        bytes32 evidence_hash;
    }

    // ─── Errors ─────────────────────────────────────────────────────────────

    error BeforeGenesis();
    error InvalidEpochConfig();

    error ShellNotRegistered(bytes32 shell_id);
    error ShellAlreadyRegistered(bytes32 shell_id);
    error InvalidShellId(bytes32 expected, bytes32 provided);

    error UnsupportedSigAlg(uint8 sig_alg);
    error InvalidKeyEncoding();
    error InvalidSignature();

    error BondAssetNotAllowed(address asset);
    error BondTooSmall(uint256 provided, uint256 minimum);

    error NotAuthorized();

    error ProposalAlreadyPending(bytes32 shell_id);
    error NoPendingProposal(bytes32 shell_id);
    error TimelockNotElapsed(uint256 current_epoch, uint256 required_epoch);

    error CertificateDoesNotExist(bytes32 shell_id);
    error CertificateShellIdMismatch(bytes32 cert_shell_id, bytes32 expected_shell_id);
    error CertificateWindowInvalid();
    error CertificateTTLExceeded(uint256 ttl_seconds);
    error InvalidAssuranceTier(uint8 assurance_tier);
    error UnsupportedTeeType(uint8 tee_type);
    error MeasurementNotAllowed(bytes32 measurement_hash, uint8 tier_class);
    error NotEnoughVerifierSignatures(uint256 provided, uint256 required);
    error TooManyVerifierSignatures(uint256 provided, uint256 max);
    error BadVerifierSigOrder();
    error InactiveVerifier(address verifier);

    error AlreadyUnbonding(bytes32 shell_id);
    error NotUnbonding(bytes32 shell_id);
    error UnbondNotReady(uint256 current_epoch, uint256 end_epoch);
    error InvalidAmount();

    error SafeHavenBondTooSmall(uint256 provided, uint256 minimum);
    error SafeHavenGuardActive(bytes32 shell_id);
    error NotSafeHaven(bytes32 shell_id);
    error SafeHavenAlreadyUnbonding(bytes32 shell_id);
    error SafeHavenNotUnbonding(bytes32 shell_id);

    error OnlyReceiptManager();
    error OnlySessionManager();

    // ─── Events ─────────────────────────────────────────────────────────────

    event ShellRegistered(bytes32 indexed shell_id, address indexed payout_address, address bond_asset, uint256 bond_amount);

    event IdentityKeyUpdateProposed(bytes32 indexed shell_id, bytes32 new_key_hash, uint256 proposed_at_epoch);
    event IdentityKeyUpdateConfirmed(bytes32 indexed shell_id, bytes32 new_key_hash);

    event OfferSignerUpdateProposed(bytes32 indexed shell_id, bytes32 new_key_hash, uint256 proposed_at_epoch);
    event OfferSignerUpdateConfirmed(bytes32 indexed shell_id, bytes32 new_key_hash);

    event RecoveryKeyUpdateProposed(bytes32 indexed shell_id, bytes32 new_key_hash, uint256 proposed_at_epoch);
    event RecoveryKeyUpdateConfirmed(bytes32 indexed shell_id, bytes32 new_key_hash);

    event CapabilityHashUpdated(bytes32 indexed shell_id, bytes32 new_capability_hash);
    event PayoutAddressUpdated(bytes32 indexed shell_id, address indexed new_payout_address);

    event CertificateSet(bytes32 indexed shell_id, bytes32 certificate_id, uint8 assurance_tier, uint256 valid_to);
    event CertificateRevoked(bytes32 indexed shell_id);

    event UnbondBegun(bytes32 indexed shell_id, uint256 amount, uint256 end_epoch);
    event UnbondFinalized(bytes32 indexed shell_id, uint256 amount);

    event SafeHavenBonded(bytes32 indexed shell_id, uint256 amount, uint256 new_total);
    event SafeHavenUnbondBegun(bytes32 indexed shell_id, uint256 amount, uint256 end_epoch);
    event SafeHavenUnbondFinalized(bytes32 indexed shell_id, uint256 amount);

    event ShellSlashed(bytes32 indexed shell_id, uint256 amount, bytes32 reason);
    event SafeHavenSlashed(bytes32 indexed shell_id, uint256 amount, address indexed challenger, uint256 challenger_reward);

    struct InitParams {
        uint256 genesis_time;
        uint256 epoch_len;
        uint256 t_shell_key_delay;
        uint256 t_unbond_shell;
        uint256 t_unbond_safehaven;
        uint256 ttl_ac_seconds;
        uint256 k_v_threshold;
        uint256 k_v_max;
        uint256 f_cert;
        address asset_verifier_stake;
        uint256 b_host_min;
        uint256 b_safehaven_min;
        uint256 bps_sh_challenger_reward;
        uint256 supported_sig_algs;
        address protocol_burn_address;
        address session_manager;
        address verifier_registry;
        address receipt_manager;
    }

    constructor(InitParams memory p, address[] memory bond_assets, uint8[] memory tee_types) {
        if (p.epoch_len == 0) revert InvalidEpochConfig();
        if (p.protocol_burn_address == address(0)) revert InvalidAmount();
        if (p.bps_sh_challenger_reward > 10_000) revert InvalidAmount();

        GENESIS_TIME = p.genesis_time;
        EPOCH_LEN = p.epoch_len;

        T_SHELL_KEY_DELAY = p.t_shell_key_delay;
        T_UNBOND_SHELL = p.t_unbond_shell;
        T_UNBOND_SAFEHAVEN = p.t_unbond_safehaven;
        TTL_AC = p.ttl_ac_seconds;

        K_V_THRESHOLD = p.k_v_threshold;
        K_V_MAX = p.k_v_max;
        F_CERT = p.f_cert;

        ASSET_VERIFIER_STAKE = IERC20(p.asset_verifier_stake);
        B_HOST_MIN = p.b_host_min;
        B_SAFEHAVEN_MIN = p.b_safehaven_min;

        BPS_SH_CHALLENGER_REWARD = p.bps_sh_challenger_reward;

        SUPPORTED_SIG_ALGS = p.supported_sig_algs;

        PROTOCOL_BURN_ADDRESS = p.protocol_burn_address;
        SESSION_MANAGER = ISessionManager(p.session_manager);
        VERIFIER_REGISTRY = IVerifierRegistry(p.verifier_registry);
        RECEIPT_MANAGER = p.receipt_manager;

        for (uint256 i = 0; i < bond_assets.length; i++) {
            bondAssets[bond_assets[i]] = true;
        }
        for (uint256 i = 0; i < tee_types.length; i++) {
            supportedTeeTypes[tee_types[i]] = true;
        }
    }

    // ─── Epoch Helpers ──────────────────────────────────────────────────────

    function currentEpoch() public view returns (uint256) {
        if (block.timestamp < GENESIS_TIME) revert BeforeGenesis();
        return (block.timestamp - GENESIS_TIME) / EPOCH_LEN;
    }

    // ─── Registration ───────────────────────────────────────────────────────

    function registerShell(
        bytes32 shell_id,
        bytes calldata identity_pubkey,
        bytes calldata offer_signer_pubkey,
        address payout_address,
        bytes32 salt,
        address bond_asset,
        uint256 bond_amount,
        bytes calldata cert,
        bytes[] calldata sigs_cert,
        bytes calldata sig
    ) external override {
        // Copy calldata -> memory to keep stack usage bounded.
        RegisterArgs memory a;
        a.shell_id = shell_id;
        a.identity_pubkey = identity_pubkey;
        a.offer_signer_pubkey = offer_signer_pubkey;
        a.payout_address = payout_address;
        a.salt = salt;
        a.bond_asset = bond_asset;
        a.bond_amount = bond_amount;
        a.cert = cert;
        a.sigs_cert = sigs_cert;
        a.sig = sig;
        a.sender = msg.sender;
        _registerShell(a);
    }

    struct RegisterArgs {
        bytes32 shell_id;
        bytes identity_pubkey;
        bytes offer_signer_pubkey;
        address payout_address;
        bytes32 salt;
        address bond_asset;
        uint256 bond_amount;
        bytes cert;
        bytes[] sigs_cert;
        bytes sig;
        address sender;
    }

    function _registerShell(RegisterArgs memory a) internal {
        bytes32 expected_id = keccak256(abi.encode(TAG_SHELL_ID, a.identity_pubkey, a.salt));
        if (a.shell_id != expected_id) revert InvalidShellId(expected_id, a.shell_id);
        if (_registered[expected_id]) revert ShellAlreadyRegistered(expected_id);

        // Enforce identity key alg support and derive its K1 address.
        address identity_addr = _decodeIdentityK1Address(a.identity_pubkey);

        // Offer signer key is K1-only (or empty to disable).
        if (a.offer_signer_pubkey.length != 0) {
            _decodeOfferSignerK1Address(a.offer_signer_pubkey);
        }

        if (!bondAssets[a.bond_asset]) revert BondAssetNotAllowed(a.bond_asset);
        if (a.bond_amount < B_HOST_MIN) revert BondTooSmall(a.bond_amount, B_HOST_MIN);

        bytes32 digest = keccak256(
            abi.encode(
                TAG_SHELL_REGISTER,
                a.shell_id,
                a.payout_address,
                a.offer_signer_pubkey,
                a.bond_asset,
                a.bond_amount,
                a.salt,
                registry_nonce,
                block.chainid
            )
        );
        _requireSig(identity_addr, digest, a.sig);

        IERC20(a.bond_asset).safeTransferFrom(a.sender, address(this), a.bond_amount);

        ShellRecord storage s = _shells[a.shell_id];
        s.shell_id = a.shell_id;
        s.identity_pubkey = a.identity_pubkey;
        s.offer_signer_pubkey = a.offer_signer_pubkey;
        s.payout_address = a.payout_address;
        s.bond_asset = a.bond_asset;
        s.bond_amount = a.bond_amount;
        s.bond_status = uint8(BondStatus.BONDED);
        s.unbond_start_epoch = 0;
        s.unbond_end_epoch = 0;
        s.recovery_pubkey = "";
        s.safehaven_bond_amount = 0;
        s.assurance_tier = 0;
        s.certificate_id = bytes32(0);
        s.capability_hash = bytes32(0);
        s.registered_epoch = currentEpoch();

        _registered[a.shell_id] = true;
        registry_nonce++;

        emit ShellRegistered(a.shell_id, a.payout_address, a.bond_asset, a.bond_amount);

        if (a.cert.length != 0) {
            _setCertificateInternal(a.shell_id, a.cert, a.sigs_cert, a.sender);
        }
    }

    // ─── Key Management ─────────────────────────────────────────────────────

    function proposeIdentityKeyUpdate(bytes32 shell_id, bytes calldata new_identity_pubkey, bytes calldata proof) external override {
        _requireRegistered(shell_id);

        KeyProposal storage p = _pendingIdentity[shell_id];
        if (p.pending) revert ProposalAlreadyPending(shell_id);

        _decodeIdentityK1Address(new_identity_pubkey); // validates SUPPORTED_SIG_ALGS and K1

        address current_identity = _decodeIdentityK1Address(_shells[shell_id].identity_pubkey);
        uint64 nonce = shell_key_nonce[shell_id];
        bytes32 digest = keccak256(
            abi.encode(TAG_SHELL_KEY_PROPOSE, shell_id, new_identity_pubkey, nonce, block.chainid)
        );
        _requireSig(current_identity, digest, proof);

        p.proposed_key = new_identity_pubkey;
        p.proposed_at_epoch = currentEpoch();
        p.pending = true;
        shell_key_nonce[shell_id] = nonce + 1;

        emit IdentityKeyUpdateProposed(shell_id, keccak256(new_identity_pubkey), p.proposed_at_epoch);
    }

    /// @dev Permissionless confirm. Timelock is the security boundary.
    function confirmIdentityKeyUpdate(bytes32 shell_id) external override {
        _requireRegistered(shell_id);

        KeyProposal storage p = _pendingIdentity[shell_id];
        if (!p.pending) revert NoPendingProposal(shell_id);

        uint256 now_epoch = currentEpoch();
        uint256 required_epoch = p.proposed_at_epoch + T_SHELL_KEY_DELAY;
        if (now_epoch < required_epoch) revert TimelockNotElapsed(now_epoch, required_epoch);

        _shells[shell_id].identity_pubkey = p.proposed_key;
        bytes32 new_hash = keccak256(p.proposed_key);
        delete _pendingIdentity[shell_id];

        emit IdentityKeyUpdateConfirmed(shell_id, new_hash);
    }

    function proposeOfferSignerUpdate(bytes32 shell_id, bytes calldata new_offer_signer_pubkey) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        if (new_offer_signer_pubkey.length == 0) {
            // Tightening: immediate disable.
            _shells[shell_id].offer_signer_pubkey = "";
            delete _pendingOfferSigner[shell_id];
            emit OfferSignerUpdateConfirmed(shell_id, bytes32(0));
            return;
        }

        _decodeOfferSignerK1Address(new_offer_signer_pubkey);

        KeyProposal storage p = _pendingOfferSigner[shell_id];
        if (p.pending) revert ProposalAlreadyPending(shell_id);

        p.proposed_key = new_offer_signer_pubkey;
        p.proposed_at_epoch = currentEpoch();
        p.pending = true;

        emit OfferSignerUpdateProposed(shell_id, keccak256(new_offer_signer_pubkey), p.proposed_at_epoch);
    }

    /// @dev Permissionless confirm. Timelock is the security boundary.
    function confirmOfferSignerUpdate(bytes32 shell_id) external override {
        _requireRegistered(shell_id);

        KeyProposal storage p = _pendingOfferSigner[shell_id];
        if (!p.pending) revert NoPendingProposal(shell_id);

        uint256 now_epoch = currentEpoch();
        uint256 required_epoch = p.proposed_at_epoch + T_SHELL_KEY_DELAY;
        if (now_epoch < required_epoch) revert TimelockNotElapsed(now_epoch, required_epoch);

        _shells[shell_id].offer_signer_pubkey = p.proposed_key;
        bytes32 new_hash = keccak256(p.proposed_key);
        delete _pendingOfferSigner[shell_id];

        emit OfferSignerUpdateConfirmed(shell_id, new_hash);
    }

    function proposeRecoveryKeyUpdate(bytes32 shell_id, bytes calldata new_recovery_pubkey) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        if (new_recovery_pubkey.length == 0) {
            // Tightening: immediate disable.
            _shells[shell_id].recovery_pubkey = "";
            delete _pendingRecovery[shell_id];
            emit RecoveryKeyUpdateConfirmed(shell_id, bytes32(0));
            return;
        }

        KeyProposal storage p = _pendingRecovery[shell_id];
        if (p.pending) revert ProposalAlreadyPending(shell_id);

        p.proposed_key = new_recovery_pubkey;
        p.proposed_at_epoch = currentEpoch();
        p.pending = true;

        emit RecoveryKeyUpdateProposed(shell_id, keccak256(new_recovery_pubkey), p.proposed_at_epoch);
    }

    /// @dev Permissionless confirm. Timelock is the security boundary.
    function confirmRecoveryKeyUpdate(bytes32 shell_id) external override {
        _requireRegistered(shell_id);

        KeyProposal storage p = _pendingRecovery[shell_id];
        if (!p.pending) revert NoPendingProposal(shell_id);

        uint256 now_epoch = currentEpoch();
        uint256 required_epoch = p.proposed_at_epoch + T_SHELL_KEY_DELAY;
        if (now_epoch < required_epoch) revert TimelockNotElapsed(now_epoch, required_epoch);

        _shells[shell_id].recovery_pubkey = p.proposed_key;
        bytes32 new_hash = keccak256(p.proposed_key);
        delete _pendingRecovery[shell_id];

        emit RecoveryKeyUpdateConfirmed(shell_id, new_hash);
    }

    function updateCapabilityHash(bytes32 shell_id, bytes32 new_capability_hash) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        _shells[shell_id].capability_hash = new_capability_hash;
        emit CapabilityHashUpdated(shell_id, new_capability_hash);
    }

    function setPayoutAddress(bytes32 shell_id, address new_payout_address) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        _shells[shell_id].payout_address = new_payout_address;
        emit PayoutAddressUpdated(shell_id, new_payout_address);
    }

    // ─── Certificate Management ─────────────────────────────────────────────

    function setCertificate(bytes32 shell_id, bytes calldata cert_data, bytes[] calldata sigs_verifiers) external override {
        _requireRegistered(shell_id);
        _setCertificateInternal(shell_id, cert_data, sigs_verifiers, msg.sender);
    }

    function revokeCertificate(bytes32 shell_id) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        ShellRecord storage s = _shells[shell_id];
        if (s.certificate_id == bytes32(0)) revert CertificateDoesNotExist(shell_id);

        s.certificate_id = bytes32(0);
        s.assurance_tier = 0;
        delete _certs[shell_id];

        emit CertificateRevoked(shell_id);
    }

    // ─── Bond Lifecycle ─────────────────────────────────────────────────────

    function beginUnbond(bytes32 shell_id, uint256 amount) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        ShellRecord storage s = _shells[shell_id];
        if (s.bond_status == uint8(BondStatus.UNBONDING)) revert AlreadyUnbonding(shell_id);
        if (amount == 0 || amount > s.bond_amount) revert InvalidAmount();

        uint256 now_epoch = currentEpoch();
        uint256 end_epoch = now_epoch + T_UNBOND_SHELL;

        s.bond_status = uint8(BondStatus.UNBONDING);
        s.unbond_start_epoch = now_epoch;
        s.unbond_end_epoch = end_epoch;
        _pendingUnbondAmount[shell_id] = amount;

        emit UnbondBegun(shell_id, amount, end_epoch);
    }

    function finalizeUnbond(bytes32 shell_id) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        ShellRecord storage s = _shells[shell_id];
        if (s.bond_status != uint8(BondStatus.UNBONDING)) revert NotUnbonding(shell_id);

        uint256 now_epoch = currentEpoch();
        if (now_epoch < s.unbond_end_epoch) revert UnbondNotReady(now_epoch, s.unbond_end_epoch);

        uint256 amount = _pendingUnbondAmount[shell_id];
        delete _pendingUnbondAmount[shell_id];

        s.bond_amount -= amount;
        s.unbond_start_epoch = 0;
        s.unbond_end_epoch = 0;
        s.bond_status = s.bond_amount == 0 ? uint8(BondStatus.WITHDRAWN) : uint8(BondStatus.BONDED);

        IERC20(s.bond_asset).safeTransfer(s.payout_address, amount);

        emit UnbondFinalized(shell_id, amount);
    }

    function bondSafeHaven(bytes32 shell_id, uint256 amount) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        if (assuranceTier(shell_id) != 3) revert NotSafeHaven(shell_id);
        if (_shells[shell_id].recovery_pubkey.length == 0) revert NotSafeHaven(shell_id);
        if (amount == 0) revert InvalidAmount();

        ShellRecord storage s = _shells[shell_id];

        // CEI: checks and effects before interaction.
        uint256 new_total = s.safehaven_bond_amount + amount;
        if (new_total < B_SAFEHAVEN_MIN) revert SafeHavenBondTooSmall(new_total, B_SAFEHAVEN_MIN);
        s.safehaven_bond_amount = new_total;

        IERC20(s.bond_asset).safeTransferFrom(msg.sender, address(this), amount);
        emit SafeHavenBonded(shell_id, amount, new_total);
    }

    function beginUnbondSafeHaven(bytes32 shell_id) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        if (_shUnbonding[shell_id]) revert SafeHavenAlreadyUnbonding(shell_id);
        if (SESSION_MANAGER.isActiveRecoveryInitiator(shell_id)) revert SafeHavenGuardActive(shell_id);

        uint256 amount = _shells[shell_id].safehaven_bond_amount;
        if (amount == 0) revert InvalidAmount();

        uint256 end_epoch = currentEpoch() + T_UNBOND_SAFEHAVEN;
        _shUnbonding[shell_id] = true;
        _shUnbondEndEpoch[shell_id] = end_epoch;
        _shUnbondAmount[shell_id] = amount;

        emit SafeHavenUnbondBegun(shell_id, amount, end_epoch);
    }

    function finalizeUnbondSafeHaven(bytes32 shell_id) external override {
        _requireRegistered(shell_id);
        _requireIdentityHolder(shell_id);

        if (!_shUnbonding[shell_id]) revert SafeHavenNotUnbonding(shell_id);

        uint256 now_epoch = currentEpoch();
        uint256 end_epoch = _shUnbondEndEpoch[shell_id];
        if (now_epoch < end_epoch) revert UnbondNotReady(now_epoch, end_epoch);

        uint256 amount = _shUnbondAmount[shell_id];

        delete _shUnbonding[shell_id];
        delete _shUnbondEndEpoch[shell_id];
        delete _shUnbondAmount[shell_id];

        _shells[shell_id].safehaven_bond_amount -= amount;
        IERC20(_shells[shell_id].bond_asset).safeTransfer(_shells[shell_id].payout_address, amount);

        emit SafeHavenUnbondFinalized(shell_id, amount);
    }

    // ─── Slashing ───────────────────────────────────────────────────────────

    function slashShell(bytes32 shell_id, uint256 amount, bytes32 reason) external override {
        if (msg.sender != RECEIPT_MANAGER) revert OnlyReceiptManager();
        _requireRegistered(shell_id);
        if (amount == 0) revert InvalidAmount();

        ShellRecord storage s = _shells[shell_id];
        if (amount > s.bond_amount) revert InvalidAmount();

        s.bond_amount -= amount;
        uint256 pending = _pendingUnbondAmount[shell_id];
        if (pending > s.bond_amount) {
            _pendingUnbondAmount[shell_id] = s.bond_amount;
        }

        IERC20(s.bond_asset).safeTransfer(PROTOCOL_BURN_ADDRESS, amount);
        emit ShellSlashed(shell_id, amount, reason);
    }

    function slashSafeHaven(bytes32 shell_id, uint256 amount, address challenger) external override {
        if (msg.sender != address(SESSION_MANAGER)) revert OnlySessionManager();
        _requireRegistered(shell_id);
        if (amount == 0) revert InvalidAmount();

        ShellRecord storage s = _shells[shell_id];
        if (amount > s.safehaven_bond_amount) revert InvalidAmount();

        s.safehaven_bond_amount -= amount;
        uint256 pending = _shUnbondAmount[shell_id];
        if (pending > s.safehaven_bond_amount) {
            _shUnbondAmount[shell_id] = s.safehaven_bond_amount;
        }

        uint256 challenger_reward = (amount * BPS_SH_CHALLENGER_REWARD) / 10_000;
        uint256 burned = amount - challenger_reward;

        IERC20(s.bond_asset).safeTransfer(challenger, challenger_reward);
        IERC20(s.bond_asset).safeTransfer(PROTOCOL_BURN_ADDRESS, burned);

        emit SafeHavenSlashed(shell_id, amount, challenger, challenger_reward);
    }

    // ─── Views ──────────────────────────────────────────────────────────────

    function getShell(bytes32 shell_id) external view override returns (ShellRecord memory) {
        if (!_registered[shell_id]) revert ShellNotRegistered(shell_id);
        return _shells[shell_id];
    }

    function assuranceTier(bytes32 shell_id) public view override returns (uint8) {
        if (!_registered[shell_id]) revert ShellNotRegistered(shell_id);
        return _effectiveAssuranceTier(shell_id);
    }

    // ─── Internal Helpers ───────────────────────────────────────────────────

    function _requireRegistered(bytes32 shell_id) internal view {
        if (!_registered[shell_id]) revert ShellNotRegistered(shell_id);
    }

    function _requireIdentityHolder(bytes32 shell_id) internal view {
        address identity_addr = _decodeIdentityK1Address(_shells[shell_id].identity_pubkey);
        if (msg.sender != identity_addr) revert NotAuthorized();
    }

    function _isSigAlgSupported(uint8 sig_alg) internal view returns (bool) {
        return (SUPPORTED_SIG_ALGS & (1 << sig_alg)) != 0;
    }

    /// @dev Canonical identity key encoding: abi.encode(uint8(sig_alg), pk_bytes).
    ///      For K1, pk_bytes = abi.encode(address).
    function _decodeIdentityK1Address(bytes memory identity_pubkey) internal view returns (address) {
        (uint8 sig_alg, bytes memory pk_bytes) = abi.decode(identity_pubkey, (uint8, bytes));
        if (!_isSigAlgSupported(sig_alg)) revert UnsupportedSigAlg(sig_alg);
        if (sig_alg != SIGALG_K1) revert UnsupportedSigAlg(sig_alg);

        address addr = abi.decode(pk_bytes, (address));
        if (addr == address(0)) revert InvalidKeyEncoding();
        return addr;
    }

    /// @dev Offer signer keys are tagged unions encoded as abi.encode(uint8(sig_alg), addr) for K1.
    function _decodeOfferSignerK1Address(bytes memory offer_signer_pubkey) internal pure returns (address) {
        uint8 sig_alg;
        address addr;
        // K1-only in v1: abi.encode(uint8(1), addr)
        (sig_alg, addr) = abi.decode(offer_signer_pubkey, (uint8, address));
        if (sig_alg != SIGALG_K1) revert UnsupportedSigAlg(sig_alg);
        if (addr == address(0)) revert InvalidKeyEncoding();
        return addr;
    }

    function _requireSig(address expected_signer, bytes32 digest, bytes memory sig) internal pure {
        address recovered = ECDSA.recover(digest, sig);
        if (recovered != expected_signer) revert InvalidSignature();
    }

    function _setCertificateInternal(bytes32 shell_id, bytes memory cert_data, bytes[] memory sigs_verifiers, address fee_payer) internal {
        ACPayload memory ac = abi.decode(cert_data, (ACPayload));

        if (ac.shell_id != shell_id) revert CertificateShellIdMismatch(ac.shell_id, shell_id);

        if (ac.assurance_tier == 0 || ac.assurance_tier > 3) revert InvalidAssuranceTier(ac.assurance_tier);
        if (!supportedTeeTypes[ac.tee_type]) revert UnsupportedTeeType(ac.tee_type);

        if (ac.valid_from > block.timestamp || block.timestamp > ac.valid_to) revert CertificateWindowInvalid();
        if (ac.valid_to - ac.valid_from > TTL_AC) revert CertificateTTLExceeded(TTL_AC);

        // Measurement allowlists are maintained in VerifierRegistry.
        if (!VERIFIER_REGISTRY.isMeasurementAllowed(ac.measurement_hash, 0)) {
            revert MeasurementNotAllowed(ac.measurement_hash, 0);
        }
        if (ac.assurance_tier == 3 && !VERIFIER_REGISTRY.isMeasurementAllowed(ac.measurement_hash, 1)) {
            revert MeasurementNotAllowed(ac.measurement_hash, 1);
        }

        uint256 sig_count = sigs_verifiers.length;
        if (sig_count < K_V_THRESHOLD) revert NotEnoughVerifierSignatures(sig_count, K_V_THRESHOLD);
        if (sig_count > K_V_MAX) revert TooManyVerifierSignatures(sig_count, K_V_MAX);

        // All AC payload fields are static types, so we can compute:
        // keccak256(abi.encode(TAG_AC, chain_id, address(this)) || cert_data)
        // which is byte-equivalent to the spec's keccak256(abi.encode(TAG_AC, chain_id, address(this), ...fields)).
        bytes32 ac_digest = keccak256(bytes.concat(abi.encode(TAG_AC, block.chainid, address(this)), cert_data));

        address prev = address(0);
        for (uint256 i = 0; i < sig_count; i++) {
            address signer = ECDSA.recover(ac_digest, sigs_verifiers[i]);
            if (signer <= prev) revert BadVerifierSigOrder();
            if (!VERIFIER_REGISTRY.isActiveVerifier(signer)) revert InactiveVerifier(signer);
            prev = signer;
        }

        if (F_CERT != 0) {
            ASSET_VERIFIER_STAKE.safeTransferFrom(fee_payer, PROTOCOL_BURN_ADDRESS, F_CERT);
        }

        ShellRecord storage s = _shells[shell_id];
        bytes32 certificate_id = keccak256(cert_data);
        s.certificate_id = certificate_id;
        s.assurance_tier = ac.assurance_tier;

        CertState storage cs = _certs[shell_id];
        cs.tee_type = ac.tee_type;
        cs.measurement_hash = ac.measurement_hash;
        cs.tcb_min = ac.tcb_min;
        cs.valid_from = ac.valid_from;
        cs.valid_to = ac.valid_to;
        cs.assurance_tier = ac.assurance_tier;
        cs.evidence_hash = ac.evidence_hash;

        emit CertificateSet(shell_id, certificate_id, ac.assurance_tier, ac.valid_to);
    }

    function _effectiveAssuranceTier(bytes32 shell_id) internal view returns (uint8) {
        ShellRecord storage s = _shells[shell_id];
        if (s.certificate_id == bytes32(0)) return 0;

        CertState storage c = _certs[shell_id];
        if (block.timestamp < c.valid_from || block.timestamp > c.valid_to) return 0;

        // Certificate becomes ineffective if measurement is revoked.
        if (!VERIFIER_REGISTRY.isMeasurementAllowed(c.measurement_hash, 0)) return 0;

        // Safe Haven suspension: if Safe Haven allowlist is violated, drop to AT2.
        if (c.assurance_tier == 3 && !VERIFIER_REGISTRY.isMeasurementAllowed(c.measurement_hash, 1)) {
            return 2;
        }

        return c.assurance_tier;
    }
}
