import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

import { heartbeatDigest } from '@gits-protocol/sdk';
import { decodeAbiParameters, encodeAbiParameters, hexToBytes, isHex, keccak256, recoverAddress, sliceHex, toBytes, toHex } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { ShellDb } from '../storage/db.js';
import { insertInterval } from '../storage/intervals.js';
import type { Metrics } from '../telemetry/metrics.js';

type SessionKeys = {
  ghostSessionKey: Hex; // abi.encode(uint8, bytes)
  shellSessionKey: Hex; // abi.encode(uint8, bytes)
};

type HeartbeatSessionState = {
  sessionId: bigint;
  keys: SessionKeys;
  shellSessionPrivateKey?: Hex;
  currentEpoch?: bigint;
  seenIntervals: Set<number>;
};

export type HeartbeatRequest = {
  sessionId: string;
  epoch: string;
  intervalIndex: string;
  sigGhost: Hex;
};

export type HeartbeatResponse = {
  accepted: boolean;
  sigShell?: Hex;
  reason?: string;
};

function bytesToAddressFromUncompressedPubkey(pubkey: Uint8Array): Hex {
  // Contract logic: address = keccak256(X||Y)[12:]
  if (pubkey.length !== 65 || pubkey[0] !== 0x04) throw new Error('pubkey must be uncompressed (65 bytes, 0x04 prefix)');
  const xy = pubkey.slice(1);
  const h = keccak256(toHex(xy));
  // last 20 bytes of hash
  const addr = ('0x' + h.slice(-40)) as Hex;
  return addr;
}

function decodeSessionKey(sessionKey: Hex): { sigAlg: number; pubkey: Uint8Array } {
  const [sigAlg, pk] = decodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], sessionKey);
  const pubkey = hexToBytes(pk as Hex);
  return { sigAlg: Number(sigAlg), pubkey };
}

export class HeartbeatService {
  private readonly chainId: bigint;
  private readonly db: ShellDb;
  private readonly metrics: Metrics;

  private readonly sessions = new Map<bigint, HeartbeatSessionState>();

  constructor(args: { chainId: bigint; db: ShellDb; metrics: Metrics }) {
    this.chainId = args.chainId;
    this.db = args.db;
    this.metrics = args.metrics;
  }

  registerSession(args: { sessionId: bigint; ghostSessionKey: Hex; shellSessionKey: Hex }): void {
    this.sessions.set(args.sessionId, {
      sessionId: args.sessionId,
      keys: { ghostSessionKey: args.ghostSessionKey, shellSessionKey: args.shellSessionKey },
      seenIntervals: new Set(),
    });
  }

  unregisterSession(sessionId: bigint): void {
    this.sessions.delete(sessionId);
  }

  setShellSessionPrivateKey(sessionId: bigint, privateKey: Hex): void {
    const s = this.sessions.get(sessionId);
    if (!s) throw new Error(`unknown session: ${sessionId}`);
    s.shellSessionPrivateKey = privateKey;
  }

  activeSessionCount(): number {
    return this.sessions.size;
  }

  async handleHeartbeat(req: HeartbeatRequest): Promise<HeartbeatResponse> {
    const sessionId = BigInt(req.sessionId);
    const epoch = BigInt(req.epoch);
    const intervalIndex = Number(BigInt(req.intervalIndex));
    if (!Number.isInteger(intervalIndex) || intervalIndex < 0) return { accepted: false, reason: 'bad_interval_index' };

    if (!isHex(req.sigGhost, { strict: true })) return { accepted: false, reason: 'bad_sig' };

    const st = this.sessions.get(sessionId);
    if (!st) return { accepted: false, reason: 'unknown_session' };

    if (st.currentEpoch === undefined || st.currentEpoch !== epoch) {
      st.currentEpoch = epoch;
      st.seenIntervals.clear();
    }
    if (st.seenIntervals.has(intervalIndex)) {
      return { accepted: false, reason: 'replay' };
    }

    const digest = heartbeatDigest({
      chain_id: this.chainId,
      session_id: sessionId,
      epoch,
      interval_index: BigInt(intervalIndex),
    });

    // Verify ghost signature against on-chain ghost session pubkey.
    let ghostOk = false;
    try {
      const g = decodeSessionKey(st.keys.ghostSessionKey);
      if (g.sigAlg !== 1) throw new Error('unsupported_sig_alg');
      const expected = bytesToAddressFromUncompressedPubkey(g.pubkey);
      const recovered = await recoverAddress({ hash: digest, signature: req.sigGhost });
      ghostOk = recovered.toLowerCase() === expected.toLowerCase();
    } catch {
      ghostOk = false;
    }

    if (!ghostOk || !st.shellSessionPrivateKey) {
      this.metrics.heartbeatsRejected += 1;
      st.seenIntervals.add(intervalIndex);
      insertInterval({
        db: this.db,
        sessionId,
        epoch,
        intervalIndex,
        vi: 0,
        sigGhost: '0x',
        sigShell: '0x',
        timestampMs: Date.now(),
      });
      return { accepted: false, reason: ghostOk ? 'no_shell_key' : 'bad_ghost_sig' };
    }

    const shellAccount = privateKeyToAccount(st.shellSessionPrivateKey);
    const sigShell = (await shellAccount.sign({ hash: digest })) as Hex;

    this.metrics.heartbeatsAccepted += 1;
    st.seenIntervals.add(intervalIndex);
    insertInterval({
      db: this.db,
      sessionId,
      epoch,
      intervalIndex,
      vi: 1,
      sigGhost: req.sigGhost,
      sigShell,
      timestampMs: Date.now(),
    });

    return { accepted: true, sigShell };
  }
}

export type NetHeartbeatRequest = {
  type: 'HeartbeatRequest';
  sessionId: string;
  epoch: string;
  intervalIndex: string;
  sigGhost: Hex;
};

export type NetHeartbeatResponse = {
  type: 'HeartbeatResponse';
  sessionId: string;
  epoch: string;
  intervalIndex: string;
  accepted: boolean;
  sigShell?: Hex;
  reason?: string;
};

export class NetHeartbeatServer {
  private readonly service: HeartbeatService;
  private readonly socketPath: string;
  private server: net.Server | undefined;

  constructor(args: { service: HeartbeatService; socketPath: string }) {
    this.service = args.service;
    this.socketPath = args.socketPath;
  }

  async start(): Promise<void> {
    if (this.server) return;

    await fs.mkdir(path.dirname(this.socketPath), { recursive: true });
    await fs.rm(this.socketPath, { force: true });

    this.server = net.createServer((socket) => {
      socket.setNoDelay(true);
      let buf = '';

      socket.on('data', async (chunk) => {
        buf += chunk.toString('utf8');
        while (true) {
          const idx = buf.indexOf('\n');
          if (idx === -1) break;
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 1);
          if (line.trim().length === 0) continue;

          let msg: NetHeartbeatRequest;
          try {
            msg = JSON.parse(line) as NetHeartbeatRequest;
          } catch {
            socket.write(JSON.stringify({ type: 'HeartbeatResponse', accepted: false, reason: 'bad_json' }) + '\n');
            continue;
          }

          if (msg.type !== 'HeartbeatRequest') {
            socket.write(JSON.stringify({ type: 'HeartbeatResponse', accepted: false, reason: 'bad_type' }) + '\n');
            continue;
          }

          const res = await this.service.handleHeartbeat({
            sessionId: msg.sessionId,
            epoch: msg.epoch,
            intervalIndex: msg.intervalIndex,
            sigGhost: msg.sigGhost,
          });

          const out: NetHeartbeatResponse = {
            type: 'HeartbeatResponse',
            sessionId: msg.sessionId,
            epoch: msg.epoch,
            intervalIndex: msg.intervalIndex,
            accepted: res.accepted,
            sigShell: res.sigShell,
            reason: res.reason,
          };
          socket.write(JSON.stringify(out) + '\n');
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.socketPath, () => resolve());
    });

    // Restrict UDS permissions (owner-only).
    await fs.chmod(this.socketPath, 0o600);
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    const s = this.server;
    this.server = undefined;
    await new Promise<void>((resolve, reject) => s.close((err) => (err ? reject(err) : resolve())));
    await fs.rm(this.socketPath, { force: true });
  }
}
