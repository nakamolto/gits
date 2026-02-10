import type { Address, Hex } from 'viem';
import type { FraudProof, Offer, SessionParams } from '@gits-protocol/sdk';
import { buildReceiptTree, generateFraudProof } from '@gits-protocol/sdk';

import type {
  EpochProvider,
  HashSigner,
  HeartbeatIpcClient,
  HeartbeatLoopOptions,
  IntervalStore,
} from './heartbeat.js';
import { HeartbeatLoop } from './heartbeat.js';

import type { ShellMonitorOptions } from './shell-monitor.js';
import { ShellMonitor } from './shell-monitor.js';

import type { EpochTicker, LeaseManagerOptions, LeaseSession } from './lease-manager.js';
import { LeaseManager } from './lease-manager.js';

export type DaemonOffer = Offer & {
  // Shell's ephemeral session public key bytes.
  shell_session_key: Hex;
};

export interface KeyManager {
  generateSessionKey(): Promise<{ publicKey: Hex; signer: HashSigner }>;
}

export interface EscrowFunder {
  fundEscrow(asset: Address, amount: bigint): Promise<void>;
}

export interface GhostWalletSdk {
  openSession(ghost_id: Hex, shell_id: Hex, params: SessionParams): Promise<void>;
  closeSession(ghost_id: Hex): Promise<void>;
  renewLease(ghost_id: Hex): Promise<void>;
  isRefreshAnchor(ghost_id: Hex, shell_id: Hex): Promise<boolean>;
}

export interface ChainEvents {
  getChainId(): Promise<bigint>;
  waitForSessionOpened(ghost_id: Hex): Promise<{ session_id: bigint; opened_epoch: bigint }>;
  waitForSessionClosed(ghost_id: Hex): Promise<{ closed_epoch: bigint }>;
}

export interface SessionStore {
  upsertSession(rec: {
    ghost_id: Hex;
    shell_id: Hex;
    session_id: bigint;
    params: SessionParams;
    opened_epoch: bigint;
  }): Promise<void>;
  markClosed(ghost_id: Hex, closed_epoch: bigint): Promise<void>;
}

export interface ReceiptObserver {
  getShellReceiptRoot(
    session_id: bigint,
    epoch: bigint,
  ): Promise<{ log_root: Hex; candidate_id: bigint } | null>;
}

export interface ReceiptChallenger {
  challengeReceipt(session_id: bigint, epoch: bigint, proof: FraudProof): Promise<void>;
}

export interface MigrationPlanner {
  startMigration(reason: string, urgency: 'routine' | 'urgent' | 'emergency'): void;
}

export interface FinalReceiptEnsurer {
  ensureFinalReceipt(session_id: bigint, epoch: bigint): Promise<void>;
}

export interface ShellNotifier {
  notifyEnsureFinalReceipt(session_id: bigint, epoch: bigint): Promise<void>;
}

export type HeartbeatLoopLike = {
  start(): void;
  stop(): void;
};

export type LeaseManagerLike = {
  start(session: LeaseSession): void;
  stop(): void;
};

export type SessionManagerOptions = {
  keys: KeyManager;
  escrow: EscrowFunder;
  wallet: GhostWalletSdk;
  chain: ChainEvents;

  epochProvider: EpochProvider;
  epochTicker: EpochTicker;

  intervalStore: IntervalStore;
  sessionStore: SessionStore;

  ipcClientFactory: (offer: DaemonOffer) => HeartbeatIpcClient;

  receiptObserver?: ReceiptObserver;
  receiptChallenger?: ReceiptChallenger;
  migrationPlanner?: MigrationPlanner;

  finalReceiptEnsurer?: FinalReceiptEnsurer;
  shellNotifier?: ShellNotifier;
  isLocalSubmitter?: (submitter_address: Address) => boolean;

  heartbeatMs: number;
  minAssuranceTier: number;
  monitorWindowSize?: number;

  migrationBufferEpochs: bigint;
  autoRenewLease: boolean;
  tenureLimitEpochs: bigint;

  createHeartbeatLoop?: (opts: HeartbeatLoopOptions) => HeartbeatLoopLike;
  createLeaseManager?: (opts: LeaseManagerOptions) => LeaseManagerLike;
  createShellMonitor?: (opts: ShellMonitorOptions) => ShellMonitor;
};

type ActiveSession = {
  ghost_id: Hex;
  shell_id: Hex;
  session_id: bigint;
  chain_id: bigint;
  params: SessionParams;
  opened_epoch: bigint;

  heartbeat: HeartbeatLoopLike;
  lease: LeaseManagerLike;
  monitor: ShellMonitor;

  migrationSignaled: boolean;
};

function normalizeHex(hex: string): string {
  if (hex.startsWith('0x')) return `0x${hex.slice(2).toLowerCase()}`;
  return `0x${hex.toLowerCase()}`;
}

export class SessionManager {
  private readonly keys: KeyManager;
  private readonly escrow: EscrowFunder;
  private readonly wallet: GhostWalletSdk;
  private readonly chain: ChainEvents;

  private readonly epochProvider: EpochProvider;
  private readonly epochTicker: EpochTicker;

  private readonly intervalStore: IntervalStore;
  private readonly sessionStore: SessionStore;
  private readonly ipcClientFactory: (offer: DaemonOffer) => HeartbeatIpcClient;

  private readonly receiptObserver?: ReceiptObserver;
  private readonly receiptChallenger?: ReceiptChallenger;
  private readonly migrationPlanner?: MigrationPlanner;

  private readonly finalReceiptEnsurer?: FinalReceiptEnsurer;
  private readonly shellNotifier?: ShellNotifier;
  private readonly isLocalSubmitter: (submitter_address: Address) => boolean;

  private readonly heartbeatMs: number;
  private readonly minAssuranceTier: number;
  private readonly monitorWindowSize: number;

  private readonly migrationBufferEpochs: bigint;
  private readonly autoRenewLease: boolean;
  private readonly tenureLimitEpochs: bigint;

  private readonly createHeartbeatLoop: (opts: HeartbeatLoopOptions) => HeartbeatLoopLike;
  private readonly createLeaseManager: (opts: LeaseManagerOptions) => LeaseManagerLike;
  private readonly createShellMonitor: (opts: ShellMonitorOptions) => ShellMonitor;

  private readonly activeByGhost = new Map<string, ActiveSession>();

  constructor(opts: SessionManagerOptions) {
    this.keys = opts.keys;
    this.escrow = opts.escrow;
    this.wallet = opts.wallet;
    this.chain = opts.chain;

    this.epochProvider = opts.epochProvider;
    this.epochTicker = opts.epochTicker;

    this.intervalStore = opts.intervalStore;
    this.sessionStore = opts.sessionStore;
    this.ipcClientFactory = opts.ipcClientFactory;

    this.receiptObserver = opts.receiptObserver;
    this.receiptChallenger = opts.receiptChallenger;
    this.migrationPlanner = opts.migrationPlanner;

    this.finalReceiptEnsurer = opts.finalReceiptEnsurer;
    this.shellNotifier = opts.shellNotifier;
    this.isLocalSubmitter = opts.isLocalSubmitter ?? (() => true);

    this.heartbeatMs = opts.heartbeatMs;
    this.minAssuranceTier = opts.minAssuranceTier;
    this.monitorWindowSize = opts.monitorWindowSize ?? 100;

    this.migrationBufferEpochs = opts.migrationBufferEpochs;
    this.autoRenewLease = opts.autoRenewLease;
    this.tenureLimitEpochs = opts.tenureLimitEpochs;

    this.createHeartbeatLoop = opts.createHeartbeatLoop ?? ((hbOpts) => new HeartbeatLoop(hbOpts));
    this.createLeaseManager = opts.createLeaseManager ?? ((lmOpts) => new LeaseManager(lmOpts));
    this.createShellMonitor =
      opts.createShellMonitor ?? ((mOpts) => new ShellMonitor({ minAssuranceTier: mOpts.minAssuranceTier, windowSize: mOpts.windowSize }));

    if (!Number.isFinite(this.heartbeatMs) || this.heartbeatMs <= 0) {
      throw new Error('SessionManager: heartbeatMs must be > 0');
    }

    if (!Number.isInteger(this.monitorWindowSize) || this.monitorWindowSize <= 0) {
      throw new Error('SessionManager: monitorWindowSize must be a positive integer');
    }

    if (this.migrationBufferEpochs < 0n) {
      throw new Error('SessionManager: migrationBufferEpochs must be >= 0');
    }
  }

  getActiveSession(ghost_id: Hex): ActiveSession | null {
    return this.activeByGhost.get(normalizeHex(ghost_id)) ?? null;
  }

  async openSession(args: { ghost_id: Hex; offer: DaemonOffer; submitter_address: Address }): Promise<ActiveSession> {
    const key = normalizeHex(args.ghost_id);
    if (this.activeByGhost.has(key)) {
      throw new Error('SessionManager.openSession: session already active for ghost');
    }

    const chain_id = await this.chain.getChainId();
    if (args.offer.chain_id !== chain_id) {
      throw new Error('SessionManager.openSession: offer.chain_id does not match configured chain_id');
    }

    const { publicKey, signer } = await this.keys.generateSessionKey();

    const max_SU = Number(args.offer.max_SU);
    if (!Number.isSafeInteger(max_SU) || max_SU < 0 || max_SU > 0xffffffff) {
      throw new Error('SessionManager.openSession: offer.max_SU must fit in a uint32');
    }

    const currentEpoch = await this.epochProvider.getCurrentEpoch();

    const params: SessionParams = {
      price_per_SU: args.offer.price_per_SU,
      max_SU,
      lease_expiry_epoch: currentEpoch + args.offer.min_lease,
      tenure_limit_epochs: this.tenureLimitEpochs,
      ghost_session_key: publicKey,
      shell_session_key: args.offer.shell_session_key,
      submitter_address: args.submitter_address,
      asset: args.offer.escrow_asset,
    };

    const requiredEscrow = params.price_per_SU * BigInt(params.max_SU);

    await this.escrow.fundEscrow(params.asset, requiredEscrow);
    await this.wallet.openSession(args.ghost_id, args.offer.shell_id, params);

    const opened = await this.chain.waitForSessionOpened(args.ghost_id);

    const monitor = this.createShellMonitor({ minAssuranceTier: this.minAssuranceTier, windowSize: this.monitorWindowSize });

    const active: ActiveSession = {
      ghost_id: args.ghost_id,
      shell_id: args.offer.shell_id,
      session_id: opened.session_id,
      chain_id,
      params,
      opened_epoch: opened.opened_epoch,
      heartbeat: { start() {}, stop() {} },
      lease: { start() {}, stop() {} },
      monitor,
      migrationSignaled: false,
    };

    const ipc = this.ipcClientFactory(args.offer);

    active.heartbeat = this.createHeartbeatLoop({
      chain_id,
      session_id: active.session_id,
      shell_session_key: args.offer.shell_session_key,
      heartbeatMs: this.heartbeatMs,
      epochProvider: this.epochProvider,
      signer,
      ipc,
      store: this.intervalStore,
      onIntervalRecorded: (rec) => {
        monitor.recordHeartbeat(rec.v_i);
        const d = monitor.shouldMigrate();
        if (d.migrate) this.signalMigration(active.ghost_id, d.reason, d.urgency);
      },
      onEpochBoundary: async (oldEpoch) => {
        await this.finalizeEpoch(active.ghost_id, active.session_id, oldEpoch, chain_id);
      },
    });

    active.lease = this.createLeaseManager({
      migrationBufferEpochs: this.migrationBufferEpochs,
      autoRenewLease: this.autoRenewLease,
      epochTicker: this.epochTicker,
      renewLease: async (ghost_id) => await this.wallet.renewLease(ghost_id),
      isRefreshAnchor: async (ghost_id, shell_id) => await this.wallet.isRefreshAnchor(ghost_id, shell_id),
      planMigration: (reason, urgency) => this.signalMigration(active.ghost_id, reason, urgency),
    });

    // Register before starting background loops so migration callbacks can find the session.
    this.activeByGhost.set(key, active);

    try {
      active.heartbeat.start();
      active.lease.start({
        ghost_id: args.ghost_id,
        shell_id: args.offer.shell_id,
        lease_expiry_epoch: params.lease_expiry_epoch,
        tenure_limit_epochs: params.tenure_limit_epochs,
        session_start_epoch: opened.opened_epoch,
      });

      await this.sessionStore.upsertSession({
        ghost_id: args.ghost_id,
        shell_id: args.offer.shell_id,
        session_id: active.session_id,
        params,
        opened_epoch: opened.opened_epoch,
      });

      return active;
    } catch (err) {
      // Best-effort cleanup on partial failures.
      active.heartbeat.stop();
      active.lease.stop();
      this.activeByGhost.delete(key);
      throw err;
    }
  }

  async closeSession(ghost_id: Hex): Promise<void> {
    const active = this.getActiveSession(ghost_id);
    if (!active) return;

    active.heartbeat.stop();
    active.lease.stop();

    await this.wallet.closeSession(ghost_id);
    const closed = await this.chain.waitForSessionClosed(ghost_id);

    await this.sessionStore.markClosed(ghost_id, closed.closed_epoch);

    await this.ensureFinalReceipt(active, closed.closed_epoch);

    this.activeByGhost.delete(normalizeHex(ghost_id));
  }

  async renewLease(ghost_id: Hex): Promise<void> {
    const active = this.getActiveSession(ghost_id);
    if (!active) {
      throw new Error('SessionManager.renewLease: no active session for ghost');
    }

    const eligible = await this.wallet.isRefreshAnchor(active.ghost_id, active.shell_id);
    if (!eligible) {
      this.signalMigration(active.ghost_id, 'trust_refresh_ineligible', 'routine');
      return;
    }

    await this.wallet.renewLease(active.ghost_id);
  }

  private async ensureFinalReceipt(active: ActiveSession, finalEpoch: bigint): Promise<void> {
    if (!this.finalReceiptEnsurer && !this.shellNotifier) return;

    const submitter = active.params.submitter_address;
    const localIsSubmitter = this.isLocalSubmitter(submitter);

    if (localIsSubmitter) {
      await this.finalReceiptEnsurer?.ensureFinalReceipt(active.session_id, finalEpoch);
    } else {
      await this.shellNotifier?.notifyEnsureFinalReceipt(active.session_id, finalEpoch);
    }
  }

  private signalMigration(ghost_id: Hex, reason: string, urgency: 'routine' | 'urgent' | 'emergency'): void {
    const active = this.getActiveSession(ghost_id);
    if (!active) return;
    if (active.migrationSignaled) return;
    active.migrationSignaled = true;
    this.migrationPlanner?.startMigration(reason, urgency);
  }

  private async finalizeEpoch(ghost_id: Hex, session_id: bigint, epoch: bigint, chain_id: bigint): Promise<void> {
    const active = this.getActiveSession(ghost_id);
    if (!active) return;

    if (!this.receiptObserver || !this.receiptChallenger) return;

    const intervals = await this.intervalStore.listIntervals(session_id, epoch);
    const tree = buildReceiptTree({ chain_id, session_id, epoch, intervals });

    const shell = await this.receiptObserver.getShellReceiptRoot(session_id, epoch);
    if (!shell) return;

    if (normalizeHex(shell.log_root) !== normalizeHex(tree.root)) {
      active.monitor.recordReceiptMismatch();

      let idx = intervals.findIndex((x) => x.v_i === 1);
      if (idx < 0) idx = 0;

      const fp = generateFraudProof(tree, idx, shell.candidate_id);
      const proof: FraudProof = {
        candidate_id: fp.candidate_id,
        interval_index: fp.interval_index,
        claimed_v: fp.claimed_v,
        leaf_hash: fp.leaf_hash,
        sibling_hashes: fp.sibling_hashes,
        sibling_sums: fp.sibling_sums,
        sig_ghost: fp.sig_ghost,
        sig_shell: fp.sig_shell,
      };

      await this.receiptChallenger.challengeReceipt(session_id, epoch, proof);
      this.signalMigration(ghost_id, 'receipt_root_mismatch', 'emergency');
    }
  }
}
