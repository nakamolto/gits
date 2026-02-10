import { hexToBytes } from 'viem';
import type { Hex } from 'viem';

import type { ShellDb } from '../storage/db.js';

export interface ReceiptCandidateInput {
  logRoot: Hex;
  suDelivered: number;
  logPtr: Hex;
}

export interface ReceiptChainWriter {
  submitReceiptCandidate(args: {
    sessionId: bigint;
    epoch: bigint;
    candidate: ReceiptCandidateInput;
    value: bigint;
  }): Promise<Hex>;
}

export class ReceiptSubmitter {
  private readonly db: ShellDb;
  private readonly chain: ReceiptChainWriter;
  private readonly bondReceipt: bigint;

  constructor(args: { db: ShellDb; chain: ReceiptChainWriter; bondReceipt: bigint }) {
    this.db = args.db;
    this.chain = args.chain;
    this.bondReceipt = args.bondReceipt;
  }

  getEpochSummary(sessionId: bigint, epoch: bigint): { logRoot: Hex; suDelivered: number } | undefined {
    const row = this.db
      .raw()
      .prepare(`SELECT log_root, su_delivered FROM epoch_summaries WHERE session_id = ? AND epoch = ?`)
      .get(sessionId, epoch) as { log_root: Buffer; su_delivered: number } | undefined;
    if (!row) return undefined;
    return { logRoot: ('0x' + row.log_root.toString('hex')) as Hex, suDelivered: Number(row.su_delivered) };
  }

  async submitIfWorthwhile(args: { sessionId: bigint; epoch: bigint }): Promise<Hex | undefined> {
    const summary = this.getEpochSummary(args.sessionId, args.epoch);
    if (!summary) return undefined;
    if (summary.suDelivered <= 0) return undefined;

    const txHash = await this.chain.submitReceiptCandidate({
      sessionId: args.sessionId,
      epoch: args.epoch,
      candidate: {
        logRoot: summary.logRoot,
        suDelivered: summary.suDelivered,
        logPtr: '0x',
      },
      value: this.bondReceipt,
    });

    this.db
      .raw()
      .prepare(
        `INSERT INTO receipt_submissions(session_id, epoch, candidate_id, tx_hash, submitted_at, finalized)
         VALUES(?, ?, ?, ?, ?, ?)
         ON CONFLICT(session_id, epoch) DO UPDATE SET tx_hash = excluded.tx_hash, submitted_at = excluded.submitted_at`,
      )
      .run(args.sessionId, args.epoch, 0, Buffer.from(hexToBytes(txHash)), Date.now(), 0);

    this.db.raw().prepare(`UPDATE epoch_summaries SET receipt_status = ? WHERE session_id = ? AND epoch = ?`).run('submitted', args.sessionId, args.epoch);

    return txHash;
  }
}

