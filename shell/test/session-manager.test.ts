import { describe, expect, it } from 'vitest';

import { encodeAbiParameters } from 'viem';
import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { ShellConfig } from '../src/config/config.js';
import { ShellDb } from '../src/storage/db.js';
import { Metrics } from '../src/telemetry/metrics.js';
import { HeartbeatService } from '../src/sessions/heartbeat.js';
import { IssuedSessionKeyStore, ShellSessionManager } from '../src/sessions/session-manager.js';

function encodeSessionKey(pubkeyUncompressed: Hex): Hex {
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pubkeyUncompressed]);
}

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

describe('session manager', () => {
  it('consumes issued session key matching on-chain encoded shell_session_key', () => {
    const store = new IssuedSessionKeyStore();
    const issued = store.issue(60_000);
    const encoded = encodeSessionKey(issued.publicKeyUncompressed);
    const consumed = store.consumeForEncodedSessionKey(encoded);
    expect(consumed?.privateKey).toEqual(issued.privateKey);
    expect(store.consumeForEncodedSessionKey(encoded)).toBeUndefined();
  });

  it('marks session unserviceable when shell key was not pre-issued', () => {
    const cfg = testConfig();
    const db = new ShellDb({ filename: ':memory:' });
    const metrics = new Metrics();
    const heartbeat = new HeartbeatService({ chainId: 1n, db, metrics });
    const store = new IssuedSessionKeyStore();
    const sm = new ShellSessionManager({ cfg, db, heartbeat, issuedKeys: store });

    const ghost = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const shell = privateKeyToAccount(('0x' + '22'.repeat(32)) as Hex);

    sm.onSessionOpened({
      sessionId: 1n,
      ghostId: ('0x' + '11'.repeat(32)) as Hex,
      shellId: cfg.identity.shellId!,
      ghostSessionKey: encodeSessionKey(ghost.publicKey),
      shellSessionKey: encodeSessionKey(shell.publicKey),
    });

    const row = db.raw().prepare('SELECT status FROM sessions WHERE session_id = 1').get() as { status: string } | undefined;
    expect(row?.status).toEqual('unserviceable');
    db.close();
  });
});

