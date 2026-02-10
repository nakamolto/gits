import { createConnection } from 'node:net';
import type { Hex } from 'viem';
import { recoverPublicKey } from 'viem';
import { heartbeatDigest } from '@gits-protocol/sdk';

export type HeartbeatRequest = {
  type: 'HeartbeatRequest';
  session_id: string; // bigint (decimal) serialized for JSON
  epoch: string; // bigint (decimal) serialized for JSON
  interval_index: number;
  sig_ghost: Hex;
};

export type HeartbeatResponse = {
  type: 'HeartbeatResponse';
  session_id: string;
  epoch: string;
  interval_index: number;
  accepted: boolean;
  sig_shell?: Hex;
  reason: string | null;
};

export type IntervalRecord = {
  session_id: bigint;
  epoch: bigint;
  interval_index: number;
  v_i: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
  ts_ms: number;
};

export type IntervalData = {
  v_i: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
};

export interface IntervalStore {
  insertInterval(rec: IntervalRecord): Promise<void>;
  listIntervals(session_id: bigint, epoch: bigint): Promise<IntervalData[]>;
}

export interface HeartbeatIpcClient {
  sendHeartbeat(req: HeartbeatRequest, timeoutMs: number): Promise<HeartbeatResponse | null>;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function parseHeartbeatResponse(line: string): HeartbeatResponse | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;

  const { type, session_id, epoch, interval_index, accepted, sig_shell, reason } = parsed;
  if (type !== 'HeartbeatResponse') return null;
  if (typeof session_id !== 'string') return null;
  if (typeof epoch !== 'string') return null;
  if (typeof interval_index !== 'number' || !Number.isInteger(interval_index) || interval_index < 0) return null;
  if (typeof accepted !== 'boolean') return null;
  if (!(typeof reason === 'string' || reason === null)) return null;
  if (accepted === true && typeof sig_shell !== 'string') return null;
  if (sig_shell !== undefined && typeof sig_shell !== 'string') return null;

  return {
    type: 'HeartbeatResponse',
    session_id,
    epoch,
    interval_index,
    accepted,
    sig_shell: sig_shell as Hex | undefined,
    reason,
  };
}

export class NetHeartbeatIpcClient implements HeartbeatIpcClient {
  private readonly socketPath: string;

  constructor(socketPath: string) {
    this.socketPath = socketPath;
  }

  async sendHeartbeat(req: HeartbeatRequest, timeoutMs: number): Promise<HeartbeatResponse | null> {
    return await new Promise<HeartbeatResponse | null>((resolve) => {
      const socket = createConnection(this.socketPath);
      let done = false;
      let buf = '';

      const finish = (res: HeartbeatResponse | null) => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve(res);
      };

      const timer = setTimeout(() => finish(null), timeoutMs);

      socket.setEncoding('utf8');

      socket.on('connect', () => {
        try {
          socket.write(`${JSON.stringify(req)}\n`);
        } catch {
          clearTimeout(timer);
          finish(null);
        }
      });

      socket.on('data', (chunk: string) => {
        buf += chunk;
        const nl = buf.indexOf('\n');
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        clearTimeout(timer);
        finish(parseHeartbeatResponse(line));
      });

      socket.on('error', () => {
        clearTimeout(timer);
        finish(null);
      });

      socket.on('close', () => {
        clearTimeout(timer);
        finish(null);
      });
    });
  }
}

export interface EpochProvider {
  getCurrentEpoch(): Promise<bigint>;
  getEpochStartSeconds(epoch: bigint): Promise<number>;
}

export interface HashSigner {
  sign(hash: Hex): Promise<Hex>;
}

export type HeartbeatLoopOptions = {
  chain_id: bigint;
  session_id: bigint;
  shell_session_key: Hex;
  heartbeatMs: number;
  epochProvider: EpochProvider;
  signer: HashSigner;
  ipc: HeartbeatIpcClient;
  store: IntervalStore;
  nowMs?: () => number;
  onEpochBoundary?: (oldEpoch: bigint, newEpoch: bigint) => Promise<void>;
  onIntervalRecorded?: (rec: IntervalRecord) => void;
  onAnomaly?: (info: { epoch: bigint; interval_index: number; reason: string }) => void;
};

function normalizeHex(hex: string): string {
  if (hex.startsWith('0x')) return `0x${hex.slice(2).toLowerCase()}`;
  return `0x${hex.toLowerCase()}`;
}

export class HeartbeatLoop {
  private readonly chain_id: bigint;
  private readonly session_id: bigint;
  private readonly shell_session_key: Hex;
  private readonly heartbeatMs: number;
  private readonly epochProvider: EpochProvider;
  private readonly signer: HashSigner;
  private readonly ipc: HeartbeatIpcClient;
  private readonly store: IntervalStore;
  private readonly nowMs: () => number;

  private readonly onEpochBoundary?: (oldEpoch: bigint, newEpoch: bigint) => Promise<void>;
  private readonly onIntervalRecorded?: (rec: IntervalRecord) => void;
  private readonly onAnomaly?: (info: { epoch: bigint; interval_index: number; reason: string }) => void;

  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private lastEpoch: bigint | null = null;
  private lastIntervalIndex: number | null = null;

  constructor(opts: HeartbeatLoopOptions) {
    this.chain_id = opts.chain_id;
    this.session_id = opts.session_id;
    this.shell_session_key = opts.shell_session_key;
    this.heartbeatMs = opts.heartbeatMs;
    this.epochProvider = opts.epochProvider;
    this.signer = opts.signer;
    this.ipc = opts.ipc;
    this.store = opts.store;
    this.nowMs = opts.nowMs ?? (() => Date.now());
    this.onEpochBoundary = opts.onEpochBoundary;
    this.onIntervalRecorded = opts.onIntervalRecorded;
    this.onAnomaly = opts.onAnomaly;

    if (!Number.isFinite(this.heartbeatMs) || this.heartbeatMs <= 0) {
      throw new Error('HeartbeatLoop: heartbeatMs must be > 0');
    }
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.tickOnce();
    }, this.heartbeatMs);
  }

  stop(): void {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }

  async tickOnce(): Promise<void> {
    if (this.inFlight) {
      this.onAnomaly?.({ epoch: this.lastEpoch ?? 0n, interval_index: this.lastIntervalIndex ?? 0, reason: 'overlap' });
      return;
    }

    this.inFlight = true;
    try {
      const epoch = await this.epochProvider.getCurrentEpoch();

      if (this.lastEpoch !== null && epoch !== this.lastEpoch) {
        try {
          await this.onEpochBoundary?.(this.lastEpoch, epoch);
        } catch {
          this.onAnomaly?.({ epoch: this.lastEpoch, interval_index: this.lastIntervalIndex ?? 0, reason: 'epoch_boundary_error' });
        }
        this.lastIntervalIndex = null;
      }

      const epochStart = await this.epochProvider.getEpochStartSeconds(epoch);
      const nowSec = this.nowMs() / 1000;
      const intervalSeconds = this.heartbeatMs / 1000;

      let interval_index = Math.floor((nowSec - epochStart) / intervalSeconds);
      if (!Number.isFinite(interval_index)) interval_index = 0;
      if (interval_index < 0) interval_index = 0;

      if (this.lastEpoch === epoch && this.lastIntervalIndex === interval_index) {
        this.onAnomaly?.({ epoch, interval_index, reason: 'duplicate_interval' });
        return;
      }

      const digest = heartbeatDigest({
        chain_id: this.chain_id,
        session_id: this.session_id,
        epoch,
        interval_index: BigInt(interval_index),
      });

      const sig_ghost = await this.signer.sign(digest);

      const req: HeartbeatRequest = {
        type: 'HeartbeatRequest',
        session_id: this.session_id.toString(),
        epoch: epoch.toString(),
        interval_index,
        sig_ghost,
      };

      const timeoutMs = Math.max(1, Math.floor(this.heartbeatMs / 2));

      let resp: HeartbeatResponse | null = null;
      try {
        resp = await this.ipc.sendHeartbeat(req, timeoutMs);
      } catch {
        resp = null;
      }

      let v_i: 0 | 1 = 0;
      let sig_shell: Hex = '0x';

      if (resp === null) {
        this.onAnomaly?.({ epoch, interval_index, reason: 'ipc_timeout' });
      } else if (
        resp.session_id !== req.session_id ||
        resp.epoch !== req.epoch ||
        resp.interval_index !== req.interval_index
      ) {
        this.onAnomaly?.({ epoch, interval_index, reason: 'invalid_response' });
      } else if (resp.accepted !== true) {
        this.onAnomaly?.({ epoch, interval_index, reason: resp.reason ?? 'rejected' });
      } else {
        sig_shell = resp.sig_shell ?? '0x';

        try {
          const recovered = await recoverPublicKey({ hash: digest, signature: sig_shell });
          const ok = normalizeHex(recovered) === normalizeHex(this.shell_session_key);
          if (ok) {
            v_i = 1;
          } else {
            v_i = 0;
            sig_shell = '0x';
            this.onAnomaly?.({ epoch, interval_index, reason: 'invalid_sig_shell' });
          }
        } catch {
          v_i = 0;
          sig_shell = '0x';
          this.onAnomaly?.({ epoch, interval_index, reason: 'invalid_sig_shell' });
        }
      }

      const rec: IntervalRecord = {
        session_id: this.session_id,
        epoch,
        interval_index,
        v_i,
        sig_ghost,
        sig_shell,
        ts_ms: this.nowMs(),
      };

      await this.store.insertInterval(rec);
      this.onIntervalRecorded?.(rec);

      this.lastEpoch = epoch;
      this.lastIntervalIndex = interval_index;
    } finally {
      this.inFlight = false;
    }
  }
}
