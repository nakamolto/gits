import { describe, expect, it, vi } from 'vitest';

import type { Hex } from 'viem';

import type { ShellConfig } from '../src/config/config.js';
import { ChainListener, type ChainListenerHandlers } from '../src/chain/listener.js';
import { ShellDb } from '../src/storage/db.js';

function testConfig(): ShellConfig {
  return {
    identity: {
      shellId: ('0x' + 'aa'.repeat(32)) as Hex,
      identityKeyPath: '~/.gits/keys/identity.json',
      offerSignerKeyPath: '~/.gits/keys/offer.json',
      recoveryKeyPath: '~/.gits/keys/recovery.json',
      payoutAddress: '0x0000000000000000000000000000000000000000',
    },
    chain: {
      rpcUrl: 'http://127.0.0.1:8545',
      chainId: 1n,
      deployment: {
        gitToken: '0x0000000000000000000000000000000000000000',
        shellRegistry: '0x0000000000000000000000000000000000000000',
        ghostRegistry: '0x0000000000000000000000000000000000000000',
        sessionManager: '0x0000000000000000000000000000000000000000',
        receiptManager: '0x0000000000000000000000000000000000000000',
        rewardsManager: '0x0000000000000000000000000000000000000000',
        verifierRegistry: '0x0000000000000000000000000000000000000000',
      },
      gasStrategy: 'auto',
    },
    offers: {
      basePricePerSU: 1n,
      asset: '0x0000000000000000000000000000000000000000',
      minLeaseEpochs: 1n,
      maxLeaseEpochs: 10n,
      dynamicPricing: false,
      premiumMultiplierBps: 0,
    },
    compute: {
      maxConcurrentSessions: 2,
      maxSUPerEpoch: 100,
      heartbeatIntervalMs: 1000,
    },
    bond: {
      bondAsset: '0x0000000000000000000000000000000000000000',
      bondAmount: 0n,
      safeHavenBondAmount: 0n,
    },
    storage: { dataDir: '/tmp' },
    network: { listenHost: '127.0.0.1', listenPort: 7777, heartbeatTransport: 'uds', heartbeatSocketPath: '/tmp/heartbeat.sock' },
  };
}

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('ChainListener', () => {
  it('stop() awaits current tick and clears loopPromise', async () => {
    const cfg = testConfig();
    const db = new ShellDb({ filename: ':memory:' });

    const handlers: ChainListenerHandlers = {
      onSessionOpened: async () => undefined,
      onSessionClosed: async () => undefined,
      onDAChallenged: async () => undefined,
      onCandidateSubmitted: async () => undefined,
      onReceiptFinalized: async () => undefined,
    };

    const listener = new ChainListener({ cfg, db, publicClient: {}, handlers });
    (listener as any).pollIntervalMs = 0;

    const d = deferred<void>();
    const tickFn = vi.fn(async () => {
      await d.promise;
    });
    (listener as any).tick = tickFn;

    await listener.start();
    expect(tickFn).toHaveBeenCalledTimes(1);

    let stopResolved = false;
    const stopP = listener.stop().then(() => {
      stopResolved = true;
    });

    await new Promise((r) => setTimeout(r, 0));
    expect(stopResolved).toBe(false);

    d.resolve(undefined);
    await stopP;
    expect(stopResolved).toBe(true);
    expect((listener as any).loopPromise).toBeNull();

    db.close();
  });
});

