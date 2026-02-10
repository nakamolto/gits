import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Address, Hex } from 'viem';

const TAG_SHELL_REGISTER = keccak256(toBytes('GITS_SHELL_REGISTER'));
const TAG_AC = keccak256(toBytes('GITS_AC'));
const TAG_ALLOW_MEASUREMENT = keccak256(toBytes('GITS_ALLOW_MEASUREMENT'));
const TAG_REVOKE_MEASUREMENT = keccak256(toBytes('GITS_REVOKE_MEASUREMENT'));
const TAG_RECOVER_AUTH = keccak256(toBytes('GITS_RECOVER_AUTH'));
const TAG_SHARE = keccak256(toBytes('GITS_SHARE'));
const TAG_SHARE_ACK = keccak256(toBytes('GITS_SHARE_ACK'));
const TAG_META_TX = keccak256(toBytes('GITS_META_TX'));
const TAG_ARTIFACT = keccak256(toBytes('GITS_ARTIFACT'));

export function shellRegistrationDigest(args: {
  shell_id: Hex;
  payout_address: Address;
  offer_signer_pubkey: Hex;
  bond_asset: Address;
  bond_amount: bigint;
  salt: Hex;
  registry_nonce: bigint;
  chain_id: bigint;
}): Hex {
  const { shell_id, payout_address, offer_signer_pubkey, bond_asset, bond_amount, salt, registry_nonce, chain_id } =
    args;

  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'address' },
        { type: 'bytes' },
        { type: 'address' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_SHELL_REGISTER, shell_id, payout_address, offer_signer_pubkey, bond_asset, bond_amount, salt, registry_nonce, chain_id],
    ),
  );
}

export function attestationCertificateDigest(args: {
  chain_id: bigint;
  shell_registry_address: Address;
  shell_id: Hex;
  tee_type: number;
  measurement_hash: Hex;
  tcb_min: Hex;
  valid_from: bigint;
  valid_to: bigint;
  assurance_tier: number;
  evidence_hash: Hex;
}): Hex {
  const {
    chain_id,
    shell_registry_address,
    shell_id,
    tee_type,
    measurement_hash,
    tcb_min,
    valid_from,
    valid_to,
    assurance_tier,
    evidence_hash,
  } = args;

  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'uint8' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint8' },
        { type: 'bytes32' },
      ],
      [
        TAG_AC,
        chain_id,
        shell_registry_address,
        shell_id,
        tee_type,
        measurement_hash,
        tcb_min,
        valid_from,
        valid_to,
        assurance_tier,
        evidence_hash,
      ],
    ),
  );
}

export function allowMeasurementDigest(args: {
  chain_id: bigint;
  verifier_registry_address: Address;
  measurement_hash: Hex;
  tier_class: number;
  nonce: bigint;
}): Hex {
  const { chain_id, verifier_registry_address, measurement_hash, tier_class, nonce } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'uint8' },
        { type: 'uint64' },
      ],
      [TAG_ALLOW_MEASUREMENT, chain_id, verifier_registry_address, measurement_hash, tier_class, nonce],
    ),
  );
}

export function revokeMeasurementDigest(args: {
  chain_id: bigint;
  verifier_registry_address: Address;
  measurement_hash: Hex;
  nonce: bigint;
}): Hex {
  const { chain_id, verifier_registry_address, measurement_hash, nonce } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'uint64' },
      ],
      [TAG_REVOKE_MEASUREMENT, chain_id, verifier_registry_address, measurement_hash, nonce],
    ),
  );
}

export function recoverAuthDigest(args: {
  chain_id: bigint;
  session_manager_address: Address;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  pk_new: Hex;
}): Hex {
  const { chain_id, session_manager_address, ghost_id, attempt_id, checkpoint_commitment, pk_new } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes' },
      ],
      [TAG_RECOVER_AUTH, chain_id, session_manager_address, ghost_id, attempt_id, checkpoint_commitment, pk_new],
    ),
  );
}

export function shareDigest(args: {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
}): Hex {
  const { chain_id, ghost_id, attempt_id, checkpoint_commitment } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
      ],
      [TAG_SHARE, chain_id, ghost_id, attempt_id, checkpoint_commitment],
    ),
  );
}

export function shareAckDigest(args: {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  shell_id: Hex;
}): Hex {
  const { chain_id, ghost_id, attempt_id, checkpoint_commitment, shell_id } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [TAG_SHARE_ACK, chain_id, ghost_id, attempt_id, checkpoint_commitment, shell_id],
    ),
  );
}

// NOTE: The v1 Part 3 spec uses EIP-712 typed data for renewLeaseWithSig and other relayed calls
// (domain name "GITSSession"). This raw-tagged helper is kept for forward compatibility only.
export function metaTxDigest(args: {
  session_manager_address: Address;
  ghost_id: Hex;
  function_selector: Hex; // bytes4
  encoded_params: Hex;
  meta_nonce: bigint;
  chain_id: bigint;
}): Hex {
  const { session_manager_address, ghost_id, function_selector, encoded_params, meta_nonce, chain_id } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'bytes4' },
        { type: 'bytes' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_META_TX, session_manager_address, ghost_id, function_selector, encoded_params, meta_nonce, chain_id],
    ),
  );
}

export function artifactDigest(args: { chain_id: bigint; artifact_type_hash: Hex; payload_hash: Hex }): Hex {
  const { chain_id, artifact_type_hash, payload_hash } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [TAG_ARTIFACT, chain_id, artifact_type_hash, payload_hash],
    ),
  );
}
