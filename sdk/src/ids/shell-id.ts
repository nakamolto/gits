import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';

const TAG_HASH = keccak256(toBytes('GITS_SHELL_ID'));

export function deriveShellId(identity_pubkey: Hex, salt: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes' }, { type: 'bytes32' }],
      [TAG_HASH, identity_pubkey, salt],
    ),
  );
}

