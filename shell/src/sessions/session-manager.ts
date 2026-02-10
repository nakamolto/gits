import { decodeAbiParameters, hexToBytes, isHex, keccak256, toBytes, toHex } from 'viem';
import type { Hex } from 'viem';

import type { ShellConfig } from '../config/config.js';
import { generateSessionKey } from '../config/keys.js';
import type { ShellDb } from '../storage/db.js';
import type { HeartbeatService } from './heartbeat.js';

type IssuedSessionKey = {
  privateKey: Hex;
  publicKeyUncompressed: Hex;
  expiresAtMs: number;
};

function decodeSessionKey(sessionKey: Hex): { sigAlg: number; pubkey: Uint8Array } {
  const [sigAlg, pk] = decodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], sessionKey);
  const pubkey = hexToBytes(pk as Hex);
  return { sigAlg: Number(sigAlg), pubkey };
}

function pubkeyHexFromEncodedSessionKey(sessionKey: Hex): Hex | undefined {
  try {
    const { sigAlg, pubkey } = decodeSessionKey(sessionKey);
    if (sigAlg !== 1) return undefined;
    if (pubkey.length !== 65 || pubkey[0] !== 0x04) return undefined;
    return toHex(pubkey) as Hex;
  } catch {
    return undefined;
  }
}

export class IssuedSessionKeyStore {
  private readonly keys = new Map<string, IssuedSessionKey>();

  issue(ttlMs: number): IssuedSessionKey {
    const key = generateSessionKey();
    const expiresAtMs = Date.now() + ttlMs;
    const issued: IssuedSessionKey = { privateKey: key.privateKey, publicKeyUncompressed: key.publicKeyUncompressed, expiresAtMs };
    this.keys.set(key.publicKeyUncompressed.toLowerCase(), issued);
    return issued;
  }

  consumeForEncodedSessionKey(sessionKey: Hex): IssuedSessionKey | undefined {
    const pub = pubkeyHexFromEncodedSessionKey(sessionKey);
    if (!pub) return undefined;
    const k = this.keys.get(pub.toLowerCase());
    if (!k) return undefined;
    if (Date.now() > k.expiresAtMs) {
      this.keys.delete(pub.toLowerCase());
      return undefined;
    }
    this.keys.delete(pub.toLowerCase());
    return k;
  }
}

export type SessionRecordStatus = 'active' | 'closed' | 'unserviceable';

export class ShellSessionManager {
  private readonly cfg: ShellConfig;
  private readonly db: ShellDb;
  private readonly heartbeat: HeartbeatService;
  private readonly issuedKeys: IssuedSessionKeyStore;

  private readonly active = new Map<bigint, { ghostId: Hex; shellId: Hex; status: SessionRecordStatus }>();

  constructor(args: { cfg: ShellConfig; db: ShellDb; heartbeat: HeartbeatService; issuedKeys: IssuedSessionKeyStore }) {
    this.cfg = args.cfg;
    this.db = args.db;
    this.heartbeat = args.heartbeat;
    this.issuedKeys = args.issuedKeys;
  }

  activeSessionCount(): number {
    return this.active.size;
  }

  listActiveSessions(): bigint[] {
    return [...this.active.keys()];
  }

  issueSessionKey(ttlMs: number): IssuedSessionKey {
    return this.issuedKeys.issue(ttlMs);
  }

  onSessionOpened(args: {
    sessionId: bigint;
    ghostId: Hex;
    shellId: Hex;
    ghostSessionKey: Hex;
    shellSessionKey: Hex;
    startEpoch?: bigint;
    paramsJson?: string;
  }): void {
    const expectedShellId = this.cfg.identity.shellId ?? (this.db.getMeta('shell_id') as Hex | undefined);
    if (!expectedShellId) throw new Error('shell_id not set');
    if (args.shellId.toLowerCase() !== expectedShellId.toLowerCase()) return;

    if (this.active.size >= this.cfg.compute.maxConcurrentSessions) {
      // Hard cap for v1. Session exists on-chain but we refuse to service it.
      this.active.set(args.sessionId, { ghostId: args.ghostId, shellId: args.shellId, status: 'unserviceable' });
      this.db
        .raw()
        .prepare(
          `INSERT INTO sessions(session_id, ghost_id, shell_id, status, start_epoch, end_epoch, session_key_public, params_json)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(session_id) DO UPDATE SET status = excluded.status, params_json = excluded.params_json`,
        )
        .run(
          args.sessionId,
          Buffer.from(hexToBytes(args.ghostId)),
          Buffer.from(hexToBytes(args.shellId)),
          'unserviceable',
          args.startEpoch ?? 0n,
          null,
          null,
          args.paramsJson ?? null,
        );
      return;
    }

    const issued = this.issuedKeys.consumeForEncodedSessionKey(args.shellSessionKey);
    const status: SessionRecordStatus = issued ? 'active' : 'unserviceable';
    this.active.set(args.sessionId, { ghostId: args.ghostId, shellId: args.shellId, status });

    const pub = pubkeyHexFromEncodedSessionKey(args.shellSessionKey);
    if (issued) {
      this.heartbeat.registerSession({ sessionId: args.sessionId, ghostSessionKey: args.ghostSessionKey, shellSessionKey: args.shellSessionKey });
      this.heartbeat.setShellSessionPrivateKey(args.sessionId, issued.privateKey);
    }

    const pubBlob = pub ? Buffer.from(hexToBytes(pub)) : null;

    this.db
      .raw()
      .prepare(
        `INSERT INTO sessions(session_id, ghost_id, shell_id, status, start_epoch, end_epoch, session_key_public, params_json)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(session_id) DO UPDATE SET status = excluded.status, start_epoch = excluded.start_epoch, params_json = excluded.params_json`,
      )
      .run(
        args.sessionId,
        Buffer.from(hexToBytes(args.ghostId)),
        Buffer.from(hexToBytes(args.shellId)),
        status,
        args.startEpoch ?? 0n,
        null,
        pubBlob,
        args.paramsJson ?? null,
      );
  }

  onSessionClosed(args: { sessionId: bigint; ghostId: Hex; shellId: Hex; endEpoch?: bigint }): void {
    const existing = this.active.get(args.sessionId);
    if (existing?.status === 'active') {
      this.heartbeat.unregisterSession(args.sessionId);
    }
    this.active.delete(args.sessionId);

    this.db
      .raw()
      .prepare(`UPDATE sessions SET status = ?, end_epoch = ? WHERE session_id = ?`)
      .run('closed', args.endEpoch ?? null, args.sessionId);
  }
}
