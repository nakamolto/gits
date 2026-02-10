import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';

const TAG_SHELL_KEY_PROPOSE = keccak256(toBytes('GITS_SHELL_KEY_PROPOSE'));

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

export function ghostRotateSignerDigest(_args: unknown): Hex {
  // TODO: Tag string + ABI layout for GhostRegistry.rotateSigner() proof digest is not specified
  // in the Part 3 PDF at the time of writing. Implement once locked.
  throw new Error('TODO: ghostRotateSignerDigest not implemented');
}
