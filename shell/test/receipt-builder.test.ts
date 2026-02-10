import { describe, expect, it } from 'vitest';

import { heartbeatDigest, buildReceiptTree } from '@gits-protocol/sdk';
import { encodeAbiParameters } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { ShellDb } from '../src/storage/db.js';
import { insertInterval } from '../src/storage/intervals.js';
import { buildAndStoreReceiptTree } from '../src/receipts/receipt-builder.js';

describe('receipt builder', () => {
  it('builds merkle-sum tree from DB intervals with padding', async () => {
    const db = new ShellDb({ filename: ':memory:' });

    const chainId = 1n;
    const sessionId = 1n;
    const epoch = 2n;
    const N = 8;

    const ghost = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const shell = privateKeyToAccount(('0x' + '22'.repeat(32)) as Hex);

    const intervals = [];
    for (let i = 0; i < N; i++) {
      const v = i % 2 === 0 ? 1 : 0;
      const digest = heartbeatDigest({ chain_id: chainId, session_id: sessionId, epoch, interval_index: BigInt(i) });
      const sigGhost = v ? await ghost.sign({ hash: digest }) : ('0x' as Hex);
      const sigShell = v ? await shell.sign({ hash: digest }) : ('0x' as Hex);
      if (v) {
        insertInterval({
          db,
          sessionId,
          epoch,
          intervalIndex: i,
          vi: 1,
          sigGhost,
          sigShell,
          timestampMs: Date.now(),
        });
      }
      intervals.push({ v_i: v as 0 | 1, sig_ghost: v ? sigGhost : ('0x' as Hex), sig_shell: v ? sigShell : ('0x' as Hex) });
    }

    const { tree, summary } = buildAndStoreReceiptTree({ db, chainId, sessionId, epoch, intervalsPerEpoch: N });
    expect(summary.suDelivered).toEqual(N / 2);

    const expected = buildReceiptTree({ chain_id: chainId, session_id: sessionId, epoch, intervals });
    expect(tree.root).toEqual(expected.root);
    expect(tree.su_total).toEqual(expected.su_total);

    db.close();
  });
});

