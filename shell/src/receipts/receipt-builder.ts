import { buildReceiptTree } from '@gits-protocol/sdk';
import type { IntervalData, MerkleTree } from '@gits-protocol/sdk';
import { hexToBytes, toHex } from 'viem';
import type { Hex } from 'viem';

import type { ShellDb } from '../storage/db.js';
import { getIntervals } from '../storage/intervals.js';

export interface EpochSummary {
  sessionId: bigint;
  epoch: bigint;
  logRoot: Hex;
  suDelivered: number;
}

export function buildAndStoreReceiptTree(args: {
  db: ShellDb;
  chainId: bigint;
  sessionId: bigint;
  epoch: bigint;
  intervalsPerEpoch: number;
}): { tree: MerkleTree; summary: EpochSummary } {
  const { db, chainId, sessionId, epoch, intervalsPerEpoch } = args;
  const rows = getIntervals({ db, sessionId, epoch });

  const byIndex = new Map<number, { v_i: 0 | 1; sig_ghost: Hex; sig_shell: Hex }>();
  for (const r of rows) {
    byIndex.set(r.interval_index, {
      v_i: r.vi,
      sig_ghost: r.sig_ghost,
      sig_shell: r.sig_shell,
    });
  }

  const intervals: IntervalData[] = [];
  for (let i = 0; i < intervalsPerEpoch; i++) {
    const it = byIndex.get(i);
    if (it && it.v_i === 1) {
      intervals.push({ v_i: 1, sig_ghost: it.sig_ghost, sig_shell: it.sig_shell });
    } else {
      intervals.push({ v_i: 0, sig_ghost: '0x', sig_shell: '0x' });
    }
  }

  const tree = buildReceiptTree({ chain_id: chainId, session_id: sessionId, epoch, intervals });
  const summary: EpochSummary = {
    sessionId,
    epoch,
    logRoot: tree.root,
    suDelivered: tree.su_total,
  };

  db.raw()
    .prepare(
      `INSERT INTO epoch_summaries(session_id, epoch, log_root, su_delivered, candidate_id, receipt_status)
       VALUES(?, ?, ?, ?, NULL, NULL)
       ON CONFLICT(session_id, epoch) DO UPDATE SET log_root = excluded.log_root, su_delivered = excluded.su_delivered`,
    )
    .run(sessionId, epoch, Buffer.from(hexToBytes(tree.root)), tree.su_total);

  return { tree, summary };
}

