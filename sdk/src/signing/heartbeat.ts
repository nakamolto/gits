import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';
import type { LocalSignerAccount } from './account.js';

const TAG_HASH = keccak256(toBytes('GITS_HEARTBEAT'));

export function heartbeatDigest(args: {
  chain_id: bigint;
  session_id: bigint;
  epoch: bigint;
  interval_index: bigint;
}): Hex {
  const { chain_id, session_id, epoch, interval_index } = args;
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_HASH, chain_id, session_id, epoch, interval_index],
    ),
  );
}

export async function signHeartbeat(
  account: LocalSignerAccount,
  args: { chain_id: bigint; session_id: bigint; epoch: bigint; interval_index: bigint },
): Promise<Hex> {
  const hash = heartbeatDigest(args);
  return account.sign({ hash });
}
