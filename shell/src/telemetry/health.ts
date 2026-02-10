import type { ShellDb } from '../storage/db.js';

export interface HealthReport {
  ok: boolean;
  shellId?: string;
  chainId: string;
  lastBlock?: string;
  activeSessions: number;
}

export function buildHealthReport(args: {
  db: ShellDb;
  shellId?: string;
  chainId: bigint;
  activeSessions: number;
}): HealthReport {
  const { db, shellId, chainId, activeSessions } = args;
  const last = db.getChainCursor();
  return {
    ok: true,
    shellId,
    chainId: chainId.toString(),
    lastBlock: last ? last.toString() : undefined,
    activeSessions,
  };
}

