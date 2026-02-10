import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Address, Hex } from 'viem';
import type { LocalSignerAccount } from './account.js';

import type { RBC } from '../types/structs.js';
import { recoverAuthDigest, shareAckDigest, shareDigest } from './digests.js';

const TAG_RBC = keccak256(toBytes('GITS_RBC'));

export function rbcDigest(args: { chain_id: bigint; session_manager_address: Address; rbc: RBC }): Hex {
  const { chain_id, session_manager_address, rbc } = args;

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
        { type: 'bytes' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
      ],
      [
        TAG_RBC,
        chain_id,
        session_manager_address,
        rbc.ghost_id,
        rbc.attempt_id,
        rbc.checkpoint_commitment,
        rbc.pk_new,
        rbc.pk_transport,
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
