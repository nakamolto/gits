import type { Address, Hex } from 'viem';

// Mirrors `contracts/src/types/GITSTypes.sol` (plus Offer from the Part 3 spec, Section 13.1).

export interface RBC {
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  pk_new: Hex;
  pk_transport: Hex;
  measurement_hash: Hex;
  tcb_min: Hex;
  valid_to: bigint;
  sigs_verifiers: Hex[];
}

export interface AuthSig {
  shell_id: Hex;
  signature: Hex;
}

export interface ShareReceipt {
  shell_id: Hex;
  sig_shell: Hex;
  sig_ack: Hex;
}

export interface SessionParams {
  price_per_SU: bigint;
  max_SU: number;
  lease_expiry_epoch: bigint;
  tenure_limit_epochs: bigint;
  ghost_session_key: Hex;
  shell_session_key: Hex;
  submitter_address: Address;
  asset: Address;
}

export interface ShellRecord {
  shell_id: Hex;
  identity_pubkey: Hex;
  offer_signer_pubkey: Hex;
  payout_address: Address;
  bond_asset: Address;
  bond_amount: bigint;
  bond_status: number;
  unbond_start_epoch: bigint;
  unbond_end_epoch: bigint;
  recovery_pubkey: Hex;
  safehaven_bond_amount: bigint;
  assurance_tier: number;
  certificate_id: Hex;
  capability_hash: Hex;
  registered_epoch: bigint;
}

export interface RecoveryConfig {
  recovery_set: Hex[];
  threshold: bigint;
  bounty_asset: Address;
  bounty_total: bigint;
  bps_initiator: bigint;
}

export interface GhostRecord {
  ghost_id: Hex;
  identity_pubkey: Hex;
  wallet: Address;
  recovery_config: RecoveryConfig;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
  ptr_checkpoint: Hex;
  ptr_envelope: Hex;
  checkpoint_epoch: bigint;
  registered_epoch: bigint;
  bond_asset: Address;
  bond_amount: bigint;
  unbond_end_epoch: bigint;
}

export interface Policy {
  home_shell: Hex;
  allowed_shells: Hex[];
  trusted_shells: Hex[];
  hot_allowance: bigint;
  escape_gas: bigint;
  escape_stable: bigint;
  guardians: Hex[];
  t_guardian: bigint;
  roaming_enabled: boolean;
}

export interface PolicyDelta {
  new_home_shell: Hex;
  add_allowed_shells: Hex[];
  remove_allowed_shells: Hex[];
  add_trusted_shells: Hex[];
  remove_trusted_shells: Hex[];
  hot_allowance_delta: bigint;
  escape_gas_delta: bigint;
  escape_stable_delta: bigint;
  new_guardians: Hex[];
  new_t_guardian: bigint;
  roaming_config: Hex;
}

export interface SessionState {
  session_id: bigint;
  ghost_id: Hex;
  shell_id: Hex;
  mode: number;
  stranded_reason: number;
  lease_expiry_epoch: bigint;
  residency_start_epoch: bigint;
  residency_start_epoch_snapshot: bigint;
  residency_tenure_limit_epochs: bigint;
  session_start_epoch: bigint;
  pricing_mode: number;
  assurance_tier_snapshot: number;
  staging: boolean;
  passport_bonus_applies: boolean;
  pending_migration: boolean;
  mig_dest_shell_id: Hex;
  mig_dest_session_id: bigint;
  mig_expiry_epoch: bigint;
}

export interface ReceiptCandidate {
  log_root: Hex;
  su_delivered: number;
  log_ptr: Hex;
}

export interface FraudProof {
  candidate_id: bigint;
  interval_index: number;
  claimed_v: number;
  leaf_hash: Hex;
  sibling_hashes: Hex[];
  sibling_sums: number[];
  sig_ghost: Hex;
  sig_shell: Hex;
}

export interface FinalReceipt {
  receipt_id: Hex;
  session_id: bigint;
  epoch: bigint;
  log_root: Hex;
  su_delivered: number;
  submitter: Address;
  shell_reward_eligible: boolean;
  weight_q: bigint;
}

export interface RecoveryAttempt {
  attempt_id: bigint;
  ghost_id: Hex;
  initiator_shell_id: Hex;
  start_epoch: bigint;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
  rs_hash: Hex;
  t_required: bigint;
  bounty_snapshot: bigint;
  status: number;
}

// Part 3 spec, Section 13.1 (Offer discovery).
export interface Offer {
  offer_id: Hex;
  shell_id: Hex;
  chain_id: bigint;
  nonce: bigint;
  price_per_SU: bigint;
  escrow_asset: Address;
  min_lease: bigint;
  max_SU: bigint;
  assurance_tier: number;
  capability_hash: Hex;
  policy_tags: Hex;
  region: Hex;
  capacity: number;
  expiry: bigint;
}

