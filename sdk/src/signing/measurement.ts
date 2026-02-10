import type { Hex } from 'viem';
import { allowMeasurementDigest, revokeMeasurementDigest } from './digests.js';
import type { LocalSignerAccount } from './account.js';

export async function signAllowMeasurement(
  account: LocalSignerAccount,
  args: Parameters<typeof allowMeasurementDigest>[0],
): Promise<Hex> {
  const hash = allowMeasurementDigest(args);
  return account.sign({ hash });
}

export async function signRevokeMeasurement(
  account: LocalSignerAccount,
  args: Parameters<typeof revokeMeasurementDigest>[0],
): Promise<Hex> {
  const hash = revokeMeasurementDigest(args);
  return account.sign({ hash });
}
