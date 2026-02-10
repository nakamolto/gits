import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';

const TAG_SHELL_KEY_PROPOSE = keccak256(toBytes('GITS_SHELL_KEY_PROPOSE'));
const TAG_ROTATE = keccak256(toBytes('GITS_ROTATE'));

export function shellIdentityKeyProposeDigest(args: {
  shell_id: Hex;
  new_identity_pubkey: Hex;
  nonce: bigint;
  chain_id: bigint;
}): Hex {
  const { shell_id, new_identity_pubkey, nonce, chain_id } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_SHELL_KEY_PROPOSE, shell_id, new_identity_pubkey, nonce, chain_id],
    ),
  );
}

export function ghostRotateSignerDigest(args: {
  ghost_id: Hex;
  new_identity_pubkey: Hex;
  chain_id: bigint;
  nonce: bigint;
}): Hex {
  const { ghost_id, new_identity_pubkey, chain_id, nonce } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_ROTATE, ghost_id, new_identity_pubkey, chain_id, nonce],
    ),
  );
}
