import { describe, expect, it } from 'vitest';

import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';

import type { Address, Hex } from 'viem';

import { GhostDB } from '../src/storage/db.js';
import { GhostChainListener } from '../src/chain/listener.js';

function mkLog(args: {
  address: Address;
  eventName: string;
  blockNumber: bigint;
  logIndex: number;
  tx: Hex;
  eventArgs: any;
}) {
  return {
    address: args.address,
    eventName: args.eventName,
    blockNumber: args.blockNumber,
    logIndex: args.logIndex,
    transactionHash: args.tx,
    args: args.eventArgs,
  };
}

describe('Chain listener', () => {
  it('backfills from cursor and persists last_block; live logs update cursor', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-chain-'));
    const db = await GhostDB.open(dir);

    db.setChainCursor(100);

    const sessionManager = '0x0000000000000000000000000000000000000004' as Address;
    const verifierRegistry = '0x0000000000000000000000000000000000000007' as Address;

    const watchers: any[] = [];

    const httpClient = {
      getBlockNumber: async () => 105n,
      getLogs: async ({ address }: any) => {
        if (address === sessionManager) {
          return [
            mkLog({
              address: sessionManager,
              eventName: 'SessionOpened',
              blockNumber: 102n,
              logIndex: 0,
              tx: '0x' + 'aa'.repeat(32),
              eventArgs: {
                ghost_id: '0x' + '11'.repeat(32),
                shell_id: '0x' + '22'.repeat(32),
                session_id: 1n,
              },
            }),
          ];
        }
        if (address === verifierRegistry) {
          return [
            mkLog({
              address: verifierRegistry,
              eventName: 'MeasurementRevoked',
              blockNumber: 104n,
              logIndex: 0,
              tx: '0x' + 'bb'.repeat(32),
              eventArgs: { measurement_hash: '0x' + '33'.repeat(32) },
            }),
          ];
        }
        return [];
      },
      watchContractEvent: (opts: any) => {
        watchers.push(opts);
        return () => {
          const i = watchers.indexOf(opts);
          if (i >= 0) watchers.splice(i, 1);
        };
      },
    } as any;

    const listener = new GhostChainListener({
      db,
      httpClient,
      watchClient: httpClient,
      sessionManager,
      verifierRegistry,
    });

    const opened: any[] = [];
    listener.onSessionOpened((l) => opened.push(l));

    await listener.start();

    // Cursor advanced to latest from getBlockNumber.
    expect(db.getChainCursor()).toBe(105);
    expect(opened.length).toBe(1);

    // Watchers start from cursor + 1.
    expect(watchers.length).toBe(2);
    expect(watchers[0].fromBlock).toBe(106n);

    // Simulate a live log at block 106.
    await watchers[0].onLogs([
      mkLog({
        address: sessionManager,
        eventName: 'LeaseRenewed',
        blockNumber: 106n,
        logIndex: 1,
        tx: '0x' + 'cc'.repeat(32),
        eventArgs: { ghost_id: '0x' + '11'.repeat(32), new_expiry_epoch: 200n },
      }),
    ]);

    expect(db.getChainCursor()).toBe(106);

    await listener.stop();
    db.close();
  });
});
