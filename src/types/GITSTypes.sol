// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GITS Shared Types
/// @notice Structs, enums, and constants used across all GITS protocol contracts.
/// @dev See Part 3, Section 14 of the GITS whitepaper (gits.sh).

// ─── Enums ───────────────────────────────────────────────────────────────────

/// @notice Session mode state machine.
enum SessionMode {
    NORMAL,                // 0: Active session, all operations available
    STRANDED,              // 1: No active session — voluntary close, lease expiry, or tenure expiry
    RECOVERY_LOCKED,       // 2: Recovery initiated, awaiting recoveryRotate
    RECOVERY_STABILIZING   // 3: Recovery rotated, stabilizing before exit
}

/// @notice Reason the Ghost entered STRANDED mode.
enum StrandedReason {
    NO_SESSION,      // 0: Never had a session / initial state
    VOLUNTARY_CLOSE, // 1: Ghost closed the session
    EXPIRED          // 2: Lease or tenure expired
}

/// @notice Bond lifecycle status.
enum BondStatus {
    BONDED,    // 0
    UNBONDING, // 1
    WITHDRAWN  // 2
}

/// @notice Recovery attempt status.
enum RecoveryStatus {
    ACTIVE,  // 0: Recovery in progress
    ROTATED, // 1: recoveryRotate succeeded
    EXPIRED  // 2: Timed out via expireRecovery
}

// ─── Structs ─────────────────────────────────────────────────────────────────

/// @notice Recovery Boot Certificate (Section 12.3).
struct RBC {
    bytes32 ghost_id;
    uint64  attempt_id;            // monotonic counter per ghost_id
    bytes32 checkpoint_commitment;
    bytes   pk_new;                // new identity pubkey (canonical encoding)
    bytes   pk_transport;          // ephemeral recovery transport pubkey
    bytes32 measurement_hash;      // measured recovery runtime image hash
    bytes32 tcb_min;               // minimum TCB level required
    uint256 valid_to;              // certificate expiry (block.timestamp)
    bytes[] sigs_verifiers;        // verifier quorum signatures over rbc_digest
}

/// @notice Recovery Set member authorization signature (Section 12.3).
struct AuthSig {
    bytes32 shell_id;  // Recovery Set member
    bytes   signature; // over GITS_RECOVER_AUTH digest
}

/// @notice Safe Haven secret-share contribution attestation (Section 12.2.1).
struct ShareReceipt {
    bytes32 shell_id;  // Safe Haven that contributed a share
    bytes   sig_shell; // Shell Identity Key attestation (GITS_SHARE digest)
    bytes   sig_ack;   // Recovery VM attestation (GITS_SHARE_ACK digest)
}

/// @notice Session parameters agreed at session open (Section 10.3.2).
struct SessionParams {
    uint256 price_per_SU;          // offer price per SU in asset base units
    uint32  max_SU;                // Ghost-requested max SU per epoch
    uint256 lease_expiry_epoch;
    uint256 tenure_limit_epochs;   // Ghost-chosen tenure limit for this residency
    bytes   ghost_session_key;     // (sig_alg, pk) for heartbeat/receipt signing
    bytes   shell_session_key;     // (sig_alg, pk) for heartbeat/receipt signing
    address submitter_address;     // third-party receipt submitter
    address asset;                 // escrow/payment asset address
}

/// @notice Shell on-chain record (returned by IShellRegistry.getShell).
struct ShellRecord {
    bytes32 shell_id;
    bytes   identity_pubkey;
    bytes   offer_signer_pubkey;
    address payout_address;
    address bond_asset;
    uint256 bond_amount;
    uint8   bond_status;           // 0=bonded, 1=unbonding, 2=withdrawn
    uint256 unbond_start_epoch;
    uint256 unbond_end_epoch;
    bytes   recovery_pubkey;       // Safe Haven only (empty if not)
    uint256 safehaven_bond_amount;
    uint8   assurance_tier;        // 0..3
    bytes32 certificate_id;        // keccak256 of current AC (bytes32(0) if none)
    bytes32 capability_hash;       // keccak256 of Capability Statement
    uint256 registered_epoch;
}

/// @notice Ghost on-chain record (returned by IGhostRegistry.getGhost).
struct GhostRecord {
    bytes32        ghost_id;
    bytes          identity_pubkey;
    address        wallet;
    RecoveryConfig recovery_config;
    bytes32        checkpoint_commitment;
    bytes32        envelope_commitment;
    bytes          ptr_checkpoint;         // opaque pointer to checkpoint data
    bytes          ptr_envelope;           // opaque pointer to envelope data
    uint256        checkpoint_epoch;
    uint256        registered_epoch;
    address        bond_asset;
    uint256        bond_amount;
    uint256        unbond_end_epoch;       // 0 if not unbonding
}

/// @notice Recovery configuration (per-Ghost, stored in GhostRegistry).
struct RecoveryConfig {
    bytes32[] recovery_set;    // Safe Haven shell_ids authorized for recovery
    uint64    threshold;       // t: required sigs for recovery actions
    address   bounty_asset;    // asset for rescue bounty payments
    uint256   bounty_total;    // B_rescue_total
    uint256   bps_initiator;   // initiator share of rescue bounty (basis points)
}

/// @notice Ghost wallet execution policy (returned by IGhostWallet.getPolicy).
struct Policy {
    bytes32   home_shell;
    bytes32[] allowed_shells;
    bytes32[] trusted_shells;
    uint256   hot_allowance;     // per-epoch spend cap
    uint256   escape_gas;        // total gas reserve
    uint256   escape_stable;     // total stable reserve (incl. B_rescue_total)
    bytes[]   guardians;         // guardian public keys
    uint64    t_guardian;         // guardian quorum threshold
    bool      roaming_enabled;
}

/// @notice Policy change request (input to proposePolicyChange).
struct PolicyDelta {
    bytes32   new_home_shell;           // bytes32(0) = no change
    bytes32[] add_allowed_shells;
    bytes32[] remove_allowed_shells;
    bytes32[] add_trusted_shells;
    bytes32[] remove_trusted_shells;
    int256    hot_allowance_delta;      // signed: +increase, -decrease
    int256    escape_gas_delta;
    int256    escape_stable_delta;
    bytes[]   new_guardians;            // empty = no change; non-empty = replace entire set
    uint64    new_t_guardian;            // 0 = no change
    bytes     roaming_config;           // encoded roaming params (empty = no change)
}

/// @notice Session state (returned by ISessionManager.getSession).
struct SessionState {
    uint256 session_id;
    bytes32 ghost_id;
    bytes32 shell_id;
    uint8   mode;                              // SessionMode
    uint8   stranded_reason;                   // StrandedReason
    uint256 lease_expiry_epoch;
    uint256 residency_start_epoch;
    uint256 residency_start_epoch_snapshot;     // immutable per session
    uint256 residency_tenure_limit_epochs;
    uint256 session_start_epoch;
    uint8   pricing_mode;                      // 0=NORMAL, 1=RECOVERY
    uint8   assurance_tier_snapshot;           // Shell AT at session open
    bool    staging;                           // true for migration staging sessions
    bool    passport_bonus_applies;
    bool    pending_migration;
    bytes32 mig_dest_shell_id;
    uint256 mig_dest_session_id;
    uint256 mig_expiry_epoch;
}

/// @notice Receipt candidate (input to submitReceiptCandidate).
struct ReceiptCandidate {
    bytes32 log_root;      // Merkle-sum root hash
    uint32  su_delivered;  // claimed SU for the epoch
    bytes   log_ptr;       // optional: off-chain pointer to epoch log data
}

/// @notice Fraud proof (input to challengeReceipt).
struct FraudProof {
    uint256   candidate_id;     // monotone sequence number of the challenged candidate
    uint32    interval_index;   // the challenged leaf index i
    uint8     claimed_v;        // v_i as claimed in the candidate's tree
    bytes32   leaf_hash;        // H(leaf_i) as committed
    bytes32[] sibling_hashes;   // Merkle proof siblings (bottom to top)
    uint32[]  sibling_sums;     // corresponding sibling sums at each level
    bytes     sig_ghost;        // raw ghost signature for HB(session_id, epoch, i)
    bytes     sig_shell;        // raw shell signature for HB(session_id, epoch, i)
}

/// @notice Finalized receipt (returned by ReceiptManager.getFinalReceipt).
struct FinalReceipt {
    bytes32 receipt_id;
    uint256 session_id;
    uint256 epoch;
    bytes32 log_root;
    uint32  su_delivered;
    address submitter;
    bool    shell_reward_eligible;
    uint256 weight_q;            // Q64.64 weight (0 if ineligible)
}

/// @notice Recovery attempt state (Section 12.3).
struct RecoveryAttempt {
    uint64  attempt_id;
    bytes32 ghost_id;
    bytes32 initiator_shell_id;
    uint256 start_epoch;
    bytes32 checkpoint_commitment;
    bytes32 envelope_commitment;
    bytes32 rs_hash;                // keccak256 of snapshotted Recovery Set
    uint64  t_required;             // threshold at time of start
    uint256 bounty_snapshot;        // B_rescue_total at time of start
    uint8   status;                 // RecoveryStatus
}
