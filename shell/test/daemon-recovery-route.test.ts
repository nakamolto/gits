import http from 'node:http';

import { describe, expect, it } from 'vitest';

import type { Hex } from 'viem';

import type { ShellConfig } from '../src/config/config.js';
import { ShellDaemon } from '../src/daemon.js';

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
    network: { listenHost: '127.0.0.1', listenPort: 0, heartbeatTransport: 'uds', heartbeatSocketPath: '/tmp/heartbeat.sock' },
  };
}

async function postJson(port: number, path: string, body: unknown): Promise<{ status: number; json: any }> {
  const data = JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(data),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          const json = raw ? JSON.parse(raw) : {};
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

describe('Shell daemon recovery route', () => {
  it('serves POST /recovery/authorize when handler is configured', async () => {
    const d: any = new ShellDaemon();
    d.cfg = testConfig();
    d.authorizeHandler = async (body: any) => ({ ok: true, echo: body });

    await d.startHttpServer();
    try {
      const addr = d.httpServer.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      expect(port).toBeGreaterThan(0);

      const r1 = await postJson(port, '/recovery/authorize', { hello: 'world' });
      expect(r1.status).toBe(200);
      expect(r1.json).toHaveProperty('ok', true);
      expect(r1.json).toHaveProperty('echo');

      d.authorizeHandler = undefined;
      const r2 = await postJson(port, '/recovery/authorize', { hello: 'world' });
      expect(r2.status).toBe(404);
      expect(r2.json).toEqual({ error: 'recovery_not_configured' });
    } finally {
      await d.stopHttpServer();
    }
  });
});

