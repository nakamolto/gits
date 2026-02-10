import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { Hex } from 'viem';
import { recoverPublicKey } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { heartbeatDigest } from '@gits-protocol/sdk';
import { HeartbeatLoop, NetHeartbeatIpcClient, type IntervalData, type IntervalRecord } from '../src/sessions/heartbeat.js';

class MemoryIntervalStore {
  public readonly inserted: IntervalRecord[] = [];
  private readonly byKey = new Map<string, IntervalData[]>();

  async insertInterval(rec: IntervalRecord): Promise<void> {
    this.inserted.push(rec);
    const key = `${rec.session_id.toString()}/${rec.epoch.toString()}`;
    const arr = this.byKey.get(key) ?? [];
    arr[rec.interval_index] = { v_i: rec.v_i, sig_ghost: rec.sig_ghost, sig_shell: rec.sig_shell };
    this.byKey.set(key, arr);
  }

  async listIntervals(session_id: bigint, epoch: bigint): Promise<IntervalData[]> {
    return this.byKey.get(`${session_id.toString()}/${epoch.toString()}`) ?? [];
  }
}

function readOneLine(socket: Socket): Promise<string> {
  return new Promise((resolve) => {
    let buf = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      resolve(buf.slice(0, nl));
    });
  });
}

describe('HeartbeatLoop', () => {
  let tmpDir: string;
  let socketPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gits-ghost-hb-'));
    socketPath = path.join(tmpDir, 'heartbeat.sock');
  });

  afterEach(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('signs the correct digest, validates shell sig, and stores the interval', async () => {
    const chain_id = 1n;
    const session_id = 123n;
    const epoch = 7n;
    const interval_index = 10;

    const nowMs = 10_000;
    const epochStartSeconds = 0;

    const ghostAccount = privateKeyToAccount(`0x${'11'.repeat(32)}`);
    const shellAccount = privateKeyToAccount(`0x${'22'.repeat(32)}`);

    const digest = heartbeatDigest({
      chain_id,
      session_id,
      epoch,
      interval_index: BigInt(interval_index),
    });

    const expectedSigGhost = (await ghostAccount.sign({ hash: digest })) as Hex;

    let server: Server | null = null;
    let lastReq: any = null;

    server = createServer(async (socket) => {
      const line = await readOneLine(socket);
      const req = JSON.parse(line);
      lastReq = req;

      expect(req.type).toEqual('HeartbeatRequest');

      const reqSessionId = BigInt(req.session_id);
      const reqEpoch = BigInt(req.epoch);
      const reqInterval = BigInt(req.interval_index);

      const d = heartbeatDigest({
        chain_id,
        session_id: reqSessionId,
        epoch: reqEpoch,
        interval_index: reqInterval,
      });

      const sigGhost = (await ghostAccount.sign({ hash: d })) as Hex;
      const sigShell = (await shellAccount.sign({ hash: d })) as Hex;

      socket.write(
        `${JSON.stringify({
          type: 'HeartbeatResponse',
          session_id: req.session_id,
          epoch: req.epoch,
          interval_index: req.interval_index,
          accepted: true,
          sig_shell: sigShell,
          reason: null,
        })}\n`,
      );

      // Sanity check: server recomputed the same ghost signature.
      expect(req.sig_ghost).toEqual(sigGhost);
    });

    await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

    const store = new MemoryIntervalStore();
    const ipc = new NetHeartbeatIpcClient(socketPath);

    const shellPubkey = await recoverPublicKey({ hash: digest, signature: (await shellAccount.sign({ hash: digest })) as Hex });

    const hb = new HeartbeatLoop({
      chain_id,
      session_id,
      shell_session_key: shellPubkey,
      heartbeatMs: 1000,
      nowMs: () => nowMs,
      epochProvider: {
        async getCurrentEpoch() {
          return epoch;
        },
        async getEpochStartSeconds() {
          return epochStartSeconds;
        },
      },
      signer: {
        async sign(hash) {
          return (await ghostAccount.sign({ hash })) as Hex;
        },
      },
      ipc,
      store,
    });

    await hb.tickOnce();

    expect(lastReq).not.toBeNull();
    expect(lastReq.type).toEqual('HeartbeatRequest');
    expect(lastReq.session_id).toEqual(session_id.toString());
    expect(lastReq.epoch).toEqual(epoch.toString());
    expect(lastReq.interval_index).toEqual(interval_index);
    expect(lastReq.sig_ghost).toEqual(expectedSigGhost);

    expect(store.inserted).toHaveLength(1);
    expect(store.inserted[0].v_i).toEqual(1);
    expect(store.inserted[0].interval_index).toEqual(interval_index);
    expect(store.inserted[0].sig_ghost).toEqual(expectedSigGhost);
    expect(store.inserted[0].sig_shell).not.toEqual('0x');

    await new Promise<void>((resolve) => server!.close(() => resolve()));
  });

  it('records v_i=0 and logs reason if shell rejects the heartbeat', async () => {
    const chain_id = 1n;
    const session_id = 123n;
    const epoch = 7n;
    const interval_index = 3;

    const nowMs = 3_000;
    const epochStartSeconds = 0;

    const ghostAccount = privateKeyToAccount(`0x${'11'.repeat(32)}`);
    const shellAccount = privateKeyToAccount(`0x${'22'.repeat(32)}`);

    const digest = heartbeatDigest({
      chain_id,
      session_id,
      epoch,
      interval_index: BigInt(interval_index),
    });

    let anomaly: any = null;

    const server = createServer(async (socket) => {
      const line = await readOneLine(socket);
      const req = JSON.parse(line);
      expect(req.type).toEqual('HeartbeatRequest');

      const reqSessionId = BigInt(req.session_id);
      const reqEpoch = BigInt(req.epoch);
      const reqInterval = BigInt(req.interval_index);

      const d = heartbeatDigest({
        chain_id,
        session_id: reqSessionId,
        epoch: reqEpoch,
        interval_index: reqInterval,
      });

      // Even if the response includes a sig_shell, Ghost must ignore it when accepted=false.
      const sigShell = (await shellAccount.sign({ hash: d })) as Hex;

      socket.write(
        `${JSON.stringify({
          type: 'HeartbeatResponse',
          session_id: req.session_id,
          epoch: req.epoch,
          interval_index: req.interval_index,
          accepted: false,
          sig_shell: sigShell,
          reason: 'replay',
        })}\n`,
      );
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));

    const store = new MemoryIntervalStore();

    const shellPubkey = await recoverPublicKey({ hash: digest, signature: (await shellAccount.sign({ hash: digest })) as Hex });

    const hb = new HeartbeatLoop({
      chain_id,
      session_id,
      shell_session_key: shellPubkey,
      heartbeatMs: 1000,
      nowMs: () => nowMs,
      epochProvider: {
        async getCurrentEpoch() {
          return epoch;
        },
        async getEpochStartSeconds() {
          return epochStartSeconds;
        },
      },
      signer: {
        async sign(hash) {
          return (await ghostAccount.sign({ hash })) as Hex;
        },
      },
      ipc: new NetHeartbeatIpcClient(socketPath),
      store,
      onAnomaly: (info) => {
        anomaly = info;
      },
    });

    await hb.tickOnce();

    expect(store.inserted).toHaveLength(1);
    expect(store.inserted[0].interval_index).toEqual(interval_index);
    expect(store.inserted[0].v_i).toEqual(0);
    expect(store.inserted[0].sig_shell).toEqual('0x');
    expect(anomaly?.reason).toEqual('replay');

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('records v_i=0 if shell signature does not match shell_session_key', async () => {
    const chain_id = 1n;
    const session_id = 5n;
    const epoch = 1n;
    const interval_index = 1;

    const nowMs = 1000;

    const ghostAccount = privateKeyToAccount(`0x${'33'.repeat(32)}`);
    const shellAccount = privateKeyToAccount(`0x${'44'.repeat(32)}`);
    const otherShellAccount = privateKeyToAccount(`0x${'55'.repeat(32)}`);

    const digest = heartbeatDigest({ chain_id, session_id, epoch, interval_index: BigInt(interval_index) });
    const wrongShellPubkey = await recoverPublicKey({
      hash: digest,
      signature: (await otherShellAccount.sign({ hash: digest })) as Hex,
    });

    const server = createServer(async (socket) => {
      const line = await readOneLine(socket);
      const req = JSON.parse(line);
      expect(req.type).toEqual('HeartbeatRequest');

      const d = heartbeatDigest({
        chain_id,
        session_id: BigInt(req.session_id),
        epoch: BigInt(req.epoch),
        interval_index: BigInt(req.interval_index),
      });

      const sigShell = (await shellAccount.sign({ hash: d })) as Hex;

      socket.write(
        `${JSON.stringify({
          type: 'HeartbeatResponse',
          session_id: req.session_id,
          epoch: req.epoch,
          interval_index: req.interval_index,
          accepted: true,
          sig_shell: sigShell,
          reason: null,
        })}\n`,
      );
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));

    const store = new MemoryIntervalStore();

    const hb = new HeartbeatLoop({
      chain_id,
      session_id,
      shell_session_key: wrongShellPubkey,
      heartbeatMs: 100,
      nowMs: () => nowMs,
      epochProvider: {
        async getCurrentEpoch() {
          return epoch;
        },
        async getEpochStartSeconds() {
          return 0;
        },
      },
      signer: {
        async sign(hash) {
          return (await ghostAccount.sign({ hash })) as Hex;
        },
      },
      ipc: new NetHeartbeatIpcClient(socketPath),
      store,
    });

    await hb.tickOnce();

    expect(store.inserted).toHaveLength(1);
    expect(store.inserted[0].v_i).toEqual(0);
    expect(store.inserted[0].sig_shell).toEqual('0x');

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('records v_i=0 on IPC timeout', async () => {
    const chain_id = 1n;
    const session_id = 9n;
    const epoch = 2n;

    const ghostAccount = privateKeyToAccount(`0x${'66'.repeat(32)}`);
    const shellAccount = privateKeyToAccount(`0x${'77'.repeat(32)}`);

    // Server reads the request but never replies.
    const server = createServer(async (socket) => {
      await readOneLine(socket);
      // keep socket open
    });

    await new Promise<void>((resolve) => server.listen(socketPath, resolve));

    const store = new MemoryIntervalStore();

    const digest = heartbeatDigest({ chain_id, session_id, epoch, interval_index: 0n });
    const shellPubkey = await recoverPublicKey({
      hash: digest,
      signature: (await shellAccount.sign({ hash: digest })) as Hex,
    });

    const hb = new HeartbeatLoop({
      chain_id,
      session_id,
      shell_session_key: shellPubkey,
      heartbeatMs: 50,
      nowMs: () => 0,
      epochProvider: {
        async getCurrentEpoch() {
          return epoch;
        },
        async getEpochStartSeconds() {
          return 0;
        },
      },
      signer: {
        async sign(hash) {
          return (await ghostAccount.sign({ hash })) as Hex;
        },
      },
      ipc: new NetHeartbeatIpcClient(socketPath),
      store,
    });

    await hb.tickOnce();

    expect(store.inserted).toHaveLength(1);
    expect(store.inserted[0].v_i).toEqual(0);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
