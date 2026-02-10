import { afterEach, describe, expect, it } from 'vitest';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

import { heartbeatDigest } from '@gits-protocol/sdk';
import { encodeAbiParameters, recoverAddress } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { ShellDb } from '../src/storage/db.js';
import { HeartbeatService, NetHeartbeatServer } from '../src/sessions/heartbeat.js';
import { Metrics } from '../src/telemetry/metrics.js';

function encodeSessionKey(pubkeyUncompressed: Hex): Hex {
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pubkeyUncompressed]);
}

function readOneLine(socketPath: string, msg: unknown): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath, () => {
      client.write(JSON.stringify(msg) + '\n');
    });

    let buf = '';
    client.on('data', (chunk) => {
      buf += chunk.toString();
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      client.destroy();
      resolve(buf.slice(0, nl));
    });
    client.on('error', reject);
  });
}

describe('heartbeat IPC (snake_case wire protocol)', () => {
  let server: NetHeartbeatServer | undefined;

  afterEach(async () => {
    if (server) await server.stop();
    server = undefined;
  });

  it('accepts snake_case request and returns snake_case response', async () => {
    const socketPath = path.join(os.tmpdir(), `gits-hb-test-${randomBytes(4).toString('hex')}.sock`);
    const db = new ShellDb({ filename: ':memory:' });
    const metrics = new Metrics();
    const svc = new HeartbeatService({ chainId: 1n, db, metrics });

    const ghost = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const shell = privateKeyToAccount(('0x' + '22'.repeat(32)) as Hex);
    const sessionId = 123n;
    const epoch = 5n;
    const intervalIndex = 7;

    svc.registerSession({
      sessionId,
      ghostSessionKey: encodeSessionKey(ghost.publicKey),
      shellSessionKey: encodeSessionKey(shell.publicKey),
    });
    svc.setShellSessionPrivateKey(sessionId, ('0x' + '22'.repeat(32)) as Hex);

    server = new NetHeartbeatServer({ service: svc, socketPath });
    await server.start();

    const digest = heartbeatDigest({ chain_id: 1n, session_id: sessionId, epoch, interval_index: BigInt(intervalIndex) });
    const sigGhost = await ghost.sign({ hash: digest });

    const response = await readOneLine(socketPath, {
      type: 'HeartbeatRequest',
      session_id: sessionId.toString(),
      epoch: epoch.toString(),
      interval_index: intervalIndex,
      sig_ghost: sigGhost,
    });

    const parsed = JSON.parse(response);

    expect(parsed.type).toBe('HeartbeatResponse');
    expect(parsed.session_id).toBe(sessionId.toString());
    expect(parsed.epoch).toBe(epoch.toString());
    expect(parsed.interval_index).toBe(intervalIndex);
    expect(parsed.accepted).toBe(true);
    expect(parsed.reason).toBe(null);
    expect(parsed.sig_shell).toBeDefined();

    // Verify NO camelCase fields leaked
    expect(parsed.sessionId).toBeUndefined();
    expect(parsed.sigShell).toBeUndefined();

    const recoveredShell = await recoverAddress({ hash: digest, signature: parsed.sig_shell as Hex });
    expect(recoveredShell.toLowerCase()).toEqual(shell.address.toLowerCase());

    db.close();
  });

  it('rejects bad_request for missing fields (no crash)', async () => {
    const socketPath = path.join(os.tmpdir(), `gits-hb-test-${randomBytes(4).toString('hex')}.sock`);
    const db = new ShellDb({ filename: ':memory:' });
    const metrics = new Metrics();
    const svc = new HeartbeatService({ chainId: 1n, db, metrics });

    server = new NetHeartbeatServer({ service: svc, socketPath });
    await server.start();

    const response = await readOneLine(socketPath, { type: 'HeartbeatRequest' });
    const parsed = JSON.parse(response);

    expect(parsed.type).toBe('HeartbeatResponse');
    expect(parsed.accepted).toBe(false);
    expect(parsed.reason).toBe('bad_request');
    expect(parsed.session_id).toBe('0');
    expect(parsed.epoch).toBe('0');
    expect(parsed.interval_index).toBe(0);

    db.close();
  });
});

