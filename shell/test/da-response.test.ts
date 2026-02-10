import { describe, expect, it } from 'vitest';

import { heartbeatDigest } from '@gits-protocol/sdk';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { hexToBytes } from 'viem';

import { ShellDb } from '../src/storage/db.js';
import { insertInterval } from '../src/storage/intervals.js';
import { encodeIntervalLog } from '../src/receipts/da-responder.js';

describe('DA response encoding', () => {
  it('encodes LSB-first bitmap + ordered sig pairs', async () => {
    const db = new ShellDb({ filename: ':memory:' });

    const chainId = 1n;
    const sessionId = 9n;
    const epoch = 4n;
    const N = 10;

    const ghost = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const shell = privateKeyToAccount(('0x' + '22'.repeat(32)) as Hex);

    const ones = [0, 2, 9];
    const sigs: Array<{ g: Hex; s: Hex }> = [];
    for (const i of ones) {
      const digest = heartbeatDigest({ chain_id: chainId, session_id: sessionId, epoch, interval_index: BigInt(i) });
      const g = await ghost.sign({ hash: digest });
      const s = await shell.sign({ hash: digest });
      sigs.push({ g, s });
      insertInterval({ db, sessionId, epoch, intervalIndex: i, vi: 1, sigGhost: g, sigShell: s, timestampMs: Date.now() });
    }

    const encoded = encodeIntervalLog({ db, sessionId, epoch, intervalsPerEpoch: N });
    const bytes = hexToBytes(encoded);

    // bitmapLen = 2 bytes. Bits set at 0,2 => 0b00000101 = 0x05; bit 9 => second byte bit 1 => 0x02
    expect(bytes[0]).toEqual(0x05);
    expect(bytes[1]).toEqual(0x02);

    const expectedSigBytes: Uint8Array[] = [];
    for (const { g, s } of sigs) {
      expectedSigBytes.push(hexToBytes(g), hexToBytes(s));
    }
    const expectedLen = expectedSigBytes.reduce((n, b) => n + b.length, 0);
    const expected = new Uint8Array(expectedLen);
    let off = 0;
    for (const b of expectedSigBytes) {
      expected.set(b, off);
      off += b.length;
    }

    const sigPairs = bytes.slice(2);
    expect(Buffer.from(sigPairs).toString('hex')).toEqual(Buffer.from(expected).toString('hex'));

    db.close();
  });
});

