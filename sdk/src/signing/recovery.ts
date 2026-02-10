import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Address, Hex } from 'viem';
import type { LocalSignerAccount } from './account.js';

import type { RBC } from '../types/structs.js';
import { recoverAuthDigest, shareAckDigest, shareDigest } from './digests.js';

const TAG_RBC = keccak256(toBytes('GITS_RBC'));

export function rbcDigest(args: { chain_id: bigint; rbc: RBC }): Hex {
  const { chain_id, rbc } = args;
  const pk_new_hash = keccak256(rbc.pk_new);
  const pk_transport_hash = keccak256(rbc.pk_transport);

  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
      ],
      [
        TAG_RBC,
        chain_id,
        rbc.ghost_id,
        rbc.attempt_id,
        rbc.checkpoint_commitment,
        pk_new_hash,
        pk_transport_hash,
        rbc.measurement_hash,
        rbc.tcb_min,
        rbc.valid_to,
      ],
    ),
  );
}

export async function signRecoverAuth(
  account: LocalSignerAccount,
  args: Parameters<typeof recoverAuthDigest>[0],
): Promise<Hex> {
  const hash = recoverAuthDigest(args);
  return account.sign({ hash });
}

export async function signShare(account: LocalSignerAccount, args: Parameters<typeof shareDigest>[0]): Promise<Hex> {
  const hash = shareDigest(args);
  return account.sign({ hash });
}

export async function signShareAck(account: LocalSignerAccount, args: Parameters<typeof shareAckDigest>[0]): Promise<Hex> {
  const hash = shareAckDigest(args);
  return account.sign({ hash });
}
