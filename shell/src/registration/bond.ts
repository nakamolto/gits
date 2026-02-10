import type { Hex } from 'viem';

import type { ChainSubmitter } from '../chain/submitter.js';

export async function beginUnbond(args: { chain: ChainSubmitter; shellId: Hex; amount: bigint }): Promise<Hex> {
  return args.chain.beginUnbond(args.shellId, args.amount);
}

export async function finalizeUnbond(args: { chain: ChainSubmitter; shellId: Hex }): Promise<Hex> {
  return args.chain.finalizeUnbond(args.shellId);
}

export async function bondSafeHaven(args: { chain: ChainSubmitter; shellId: Hex; amount: bigint }): Promise<Hex> {
  return args.chain.bondSafeHaven(args.shellId, args.amount);
}

export async function beginUnbondSafeHaven(args: { chain: ChainSubmitter; shellId: Hex }): Promise<Hex> {
  const active = await args.chain.isActiveRecoveryInitiator(args.shellId);
  if (active) throw new Error('cannot begin safehaven unbond: shell is active recovery initiator');
  return args.chain.beginUnbondSafeHaven(args.shellId);
}

export async function finalizeUnbondSafeHaven(args: { chain: ChainSubmitter; shellId: Hex }): Promise<Hex> {
  return args.chain.finalizeUnbondSafeHaven(args.shellId);
}

