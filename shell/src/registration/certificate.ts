import type { Hex } from 'viem';

import type { ChainSubmitter } from '../chain/submitter.js';

export async function setCertificate(args: { chain: ChainSubmitter; shellId: Hex; certData: Hex; sigsVerifiers: Hex[] }): Promise<Hex> {
  return args.chain.setCertificate(args.shellId, args.certData, args.sigsVerifiers);
}

export async function revokeCertificate(args: { chain: ChainSubmitter; shellId: Hex }): Promise<Hex> {
  return args.chain.revokeCertificate(args.shellId);
}

