import { hexToBytes, isHex } from 'viem';
import type { Hex } from 'viem';

import type { ShellDb } from '../storage/db.js';
import { getIntervals } from '../storage/intervals.js';
import type { Metrics } from '../telemetry/metrics.js';

export interface DAChainWriter {
  publishReceiptLog(args: { sessionId: bigint; epoch: bigint; candidateId: bigint; encodedLog: Hex }): Promise<Hex>;
}

export function encodeIntervalLog(args: { db: ShellDb; sessionId: bigint; epoch: bigint; intervalsPerEpoch: number }): Hex {
  const { db, sessionId, epoch, intervalsPerEpoch } = args;
  const rows = getIntervals({ db, sessionId, epoch });

  const byIndex = new Map<number, { vi: 0 | 1; sigGhost: Hex; sigShell: Hex }>();
  for (const r of rows) {
    byIndex.set(r.interval_index, { vi: r.vi, sigGhost: r.sig_ghost, sigShell: r.sig_shell });
  }

  const bitmapLen = Math.floor((intervalsPerEpoch + 7) / 8);
  const bitmap = new Uint8Array(bitmapLen);
  const sigParts: Uint8Array[] = [];

  for (let i = 0; i < intervalsPerEpoch; i++) {
    const it = byIndex.get(i);
    if (!it || it.vi !== 1) continue;

    // LSB-first packing.
    bitmap[Math.floor(i / 8)] |= 1 << (i % 8);

    if (!isHex(it.sigGhost, { strict: true }) || !isHex(it.sigShell, { strict: true })) {
      throw new Error(`invalid signature hex at interval ${i}`);
    }
    const g = hexToBytes(it.sigGhost);
    const s = hexToBytes(it.sigShell);
    if (g.length !== 65 || s.length !== 65) throw new Error(`expected 65-byte sigs for interval ${i}`);
    sigParts.push(g, s);
  }

  const sigTotal = sigParts.reduce((n, b) => n + b.length, 0);
  const sigPairs = new Uint8Array(sigTotal);
  let off = 0;
  for (const p of sigParts) {
    sigPairs.set(p, off);
    off += p.length;
  }

  const out = new Uint8Array(bitmap.length + sigPairs.length);
  out.set(bitmap, 0);
  out.set(sigPairs, bitmap.length);
  return ('0x' + Buffer.from(out).toString('hex')) as Hex;
}

export class DAResponder {
  private readonly db: ShellDb;
  private readonly chain: DAChainWriter;
  private readonly metrics: Metrics;
  private readonly intervalsPerEpoch: number;

  constructor(args: { db: ShellDb; chain: DAChainWriter; metrics: Metrics; intervalsPerEpoch: number }) {
    this.db = args.db;
    this.chain = args.chain;
    this.metrics = args.metrics;
    this.intervalsPerEpoch = args.intervalsPerEpoch;
  }

  async respondToChallenge(args: { sessionId: bigint; epoch: bigint; candidateId: bigint }): Promise<Hex> {
    const encodedLog = encodeIntervalLog({
      db: this.db,
      sessionId: args.sessionId,
      epoch: args.epoch,
      intervalsPerEpoch: this.intervalsPerEpoch,
    });
    this.metrics.daResponses += 1;
    return this.chain.publishReceiptLog({
      sessionId: args.sessionId,
      epoch: args.epoch,
      candidateId: args.candidateId,
      encodedLog,
    });
  }
}

