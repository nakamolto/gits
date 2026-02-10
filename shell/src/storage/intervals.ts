import type { Hex } from 'viem';
import { bytesToHex, hexToBytes, isHex } from 'viem';

import type { ShellDb } from './db.js';

export type IntervalRow = {
  session_id: bigint;
  epoch: bigint;
  interval_index: number;
  vi: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
  timestamp: number;
};

function blobToHex(b: Buffer | null | undefined): Hex {
  if (!b || b.length === 0) return '0x';
  return bytesToHex(b) as Hex;
}

function hexToBlob(h: Hex | null | undefined): Buffer | null {
  if (!h) return null;
  if (!isHex(h, { strict: true })) throw new Error('expected hex');
  const bytes = hexToBytes(h);
  return bytes.length === 0 ? null : Buffer.from(bytes);
}

export function insertInterval(args: {
  db: ShellDb;
  sessionId: bigint;
  epoch: bigint;
  intervalIndex: number;
  vi: 0 | 1;
  sigGhost: Hex;
  sigShell: Hex;
  timestampMs: number;
}): void {
  const { db, sessionId, epoch, intervalIndex, vi, sigGhost, sigShell, timestampMs } = args;
  db.raw()
    .prepare(
      `INSERT INTO intervals(session_id, epoch, interval_index, vi, sig_ghost, sig_shell, timestamp)
       VALUES(?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_id, epoch, interval_index) DO UPDATE SET
         vi = excluded.vi,
         sig_ghost = excluded.sig_ghost,
         sig_shell = excluded.sig_shell,
         timestamp = excluded.timestamp`,
    )
    .run(
      sessionId,
      epoch,
      intervalIndex,
      vi,
      hexToBlob(sigGhost),
      hexToBlob(sigShell),
      Math.floor(timestampMs),
    );
}

export function getIntervals(args: { db: ShellDb; sessionId: bigint; epoch: bigint }): IntervalRow[] {
  const { db, sessionId, epoch } = args;
  const rows = db
    .raw()
    .prepare(
      `SELECT session_id, epoch, interval_index, vi, sig_ghost, sig_shell, timestamp
       FROM intervals
       WHERE session_id = ? AND epoch = ?
       ORDER BY interval_index ASC`,
    )
    .all(sessionId, epoch) as Array<{
    session_id: number | bigint;
    epoch: number | bigint;
    interval_index: number;
    vi: number;
    sig_ghost: Buffer | null;
    sig_shell: Buffer | null;
    timestamp: number;
  }>;

  return rows.map((r) => ({
    session_id: typeof r.session_id === 'bigint' ? r.session_id : BigInt(r.session_id),
    epoch: typeof r.epoch === 'bigint' ? r.epoch : BigInt(r.epoch),
    interval_index: r.interval_index,
    vi: (r.vi ? 1 : 0) as 0 | 1,
    sig_ghost: blobToHex(r.sig_ghost),
    sig_shell: blobToHex(r.sig_shell),
    timestamp: r.timestamp,
  }));
}

export function countDeliveredSU(args: { db: ShellDb; sessionId: bigint; epoch: bigint }): number {
  const { db, sessionId, epoch } = args;
  const row = db
    .raw()
    .prepare(`SELECT COALESCE(SUM(vi), 0) AS su FROM intervals WHERE session_id = ? AND epoch = ?`)
    .get(sessionId, epoch) as { su: number };
  return Number(row.su ?? 0);
}

