import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Address, Hex } from 'viem';

const TAG_HASH = keccak256(toBytes('GITS_GHOST_ID'));

export function deriveGhostId(identity_pubkey: Hex, wallet: Address, salt: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes' },
        { type: 'address' },
        { type: 'bytes32' },
      ],
      [TAG_HASH, identity_pubkey, wallet, salt],
    ),
  );
}

