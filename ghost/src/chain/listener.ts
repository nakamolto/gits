import type { Address, Hex } from 'viem';
import { parseAbiItem } from 'viem';
import type { PublicClient } from 'viem';

import type { GhostDB } from '../storage/db.js';

export type DecodedLog<TArgs> = {
  address: Address;
  eventName: string;
  args: TArgs;
  blockNumber: bigint;
  transactionHash: Hex;
  logIndex: number;
};

export type ListenerUnsubscribe = () => void;

type Handler<TArgs> = (log: DecodedLog<TArgs>) => void | Promise<void>;

type EventMap = {
  SessionOpened: { ghost_id: Hex; shell_id: Hex; session_id: bigint };
  SessionClosed: { ghost_id: Hex; shell_id: Hex; session_id: bigint };
  LeaseRenewed: { ghost_id: Hex; new_expiry_epoch: bigint };
  MigrationStarted: { ghost_id: Hex; to_shell_id: Hex; mig_expiry_epoch: bigint };
  MigrationFinalized: { ghost_id: Hex; to_shell_id: Hex; new_session_id: bigint };
  RecoveryStarted: { ghost_id: Hex; attempt_id: bigint; initiator_shell_id: Hex };
  RecoveryRotated: { ghost_id: Hex; attempt_id: bigint };
  RecoveryExpired: { ghost_id: Hex; attempt_id: bigint };
  RecoveryExited: { ghost_id: Hex };
  ModeChanged: { ghost_id: Hex; old_mode: bigint; new_mode: bigint };
  VerifierSlashed: { verifier: Address; asset: Address; amount: bigint; reason: Hex };
  MeasurementRevoked: { measurement_hash: Hex };
};

const SESSION_MANAGER_EVENTS = [
  parseAbiItem('event SessionOpened(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)'),
  parseAbiItem('event SessionClosed(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)'),
  parseAbiItem('event LeaseRenewed(bytes32 indexed ghost_id, uint256 new_expiry_epoch)'),
  parseAbiItem('event MigrationStarted(bytes32 indexed ghost_id, bytes32 indexed to_shell_id, uint256 mig_expiry_epoch)'),
  parseAbiItem('event MigrationFinalized(bytes32 indexed ghost_id, bytes32 indexed to_shell_id, uint256 new_session_id)'),
  parseAbiItem('event RecoveryStarted(bytes32 indexed ghost_id, uint64 attempt_id, bytes32 initiator_shell_id)'),
  parseAbiItem('event RecoveryRotated(bytes32 indexed ghost_id, uint64 attempt_id)'),
  parseAbiItem('event RecoveryExpired(bytes32 indexed ghost_id, uint64 attempt_id)'),
  parseAbiItem('event RecoveryExited(bytes32 indexed ghost_id)'),
  parseAbiItem('event ModeChanged(bytes32 indexed ghost_id, uint8 old_mode, uint8 new_mode)'),
] as const;

const VERIFIER_REGISTRY_EVENTS = [
  parseAbiItem('event VerifierSlashed(address indexed verifier, address asset, uint256 amount, bytes32 reason)'),
  parseAbiItem('event MeasurementRevoked(bytes32 indexed measurement_hash)'),
] as const;

function toCursor(blockNumber: bigint): number {
  // Blocks are safely under 2^53 for the foreseeable future.
  return Number(blockNumber);
}

export class GhostChainListener {
  private readonly db: GhostDB;
  private readonly httpClient: PublicClient;
  private readonly watchClient: PublicClient;
  private readonly sessionManager: Address;
  private readonly verifierRegistry: Address;

  private readonly handlers: { [K in keyof EventMap]?: Set<Handler<EventMap[K]>> } = {};
  private unwatchFns: Array<() => void> = [];
  private started = false;

  constructor(args: {
    db: GhostDB;
    httpClient: PublicClient;
    watchClient?: PublicClient;
    sessionManager: Address;
    verifierRegistry: Address;
  }) {
    this.db = args.db;
    this.httpClient = args.httpClient;
    this.watchClient = args.watchClient ?? args.httpClient;
    this.sessionManager = args.sessionManager;
    this.verifierRegistry = args.verifierRegistry;
  }

  // ─── Public subscription helpers ───────────────────────────────────────

  private on<K extends keyof EventMap>(eventName: K, handler: Handler<EventMap[K]>): ListenerUnsubscribe {
    let set = this.handlers[eventName] as Set<Handler<EventMap[K]>> | undefined;
    if (!set) {
      set = new Set<Handler<EventMap[K]>>();
      (this.handlers as any)[eventName] = set;
    }
    set.add(handler);
    return () => set.delete(handler);
  }

  onSessionOpened(h: Handler<EventMap['SessionOpened']>): ListenerUnsubscribe {
    return this.on('SessionOpened', h);
  }
  onSessionClosed(h: Handler<EventMap['SessionClosed']>): ListenerUnsubscribe {
    return this.on('SessionClosed', h);
  }
  onLeaseRenewed(h: Handler<EventMap['LeaseRenewed']>): ListenerUnsubscribe {
    return this.on('LeaseRenewed', h);
  }
  onMigrationStarted(h: Handler<EventMap['MigrationStarted']>): ListenerUnsubscribe {
    return this.on('MigrationStarted', h);
  }
  onMigrationFinalized(h: Handler<EventMap['MigrationFinalized']>): ListenerUnsubscribe {
    return this.on('MigrationFinalized', h);
  }
  onRecoveryStarted(h: Handler<EventMap['RecoveryStarted']>): ListenerUnsubscribe {
    return this.on('RecoveryStarted', h);
  }
  onRecoveryRotated(h: Handler<EventMap['RecoveryRotated']>): ListenerUnsubscribe {
    return this.on('RecoveryRotated', h);
  }
  onRecoveryExpired(h: Handler<EventMap['RecoveryExpired']>): ListenerUnsubscribe {
    return this.on('RecoveryExpired', h);
  }
  onRecoveryExited(h: Handler<EventMap['RecoveryExited']>): ListenerUnsubscribe {
    return this.on('RecoveryExited', h);
  }
  onModeChanged(h: Handler<EventMap['ModeChanged']>): ListenerUnsubscribe {
    return this.on('ModeChanged', h);
  }
  onVerifierSlashed(h: Handler<EventMap['VerifierSlashed']>): ListenerUnsubscribe {
    return this.on('VerifierSlashed', h);
  }
  onMeasurementRevoked(h: Handler<EventMap['MeasurementRevoked']>): ListenerUnsubscribe {
    return this.on('MeasurementRevoked', h);
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;

    await this.backfillFromCursor();

    const fromBlock = BigInt(this.db.getChainCursor() + 1);

    // Live watching. We intentionally watch the entire ABI and dispatch by `eventName`.
    const unwatchSession = this.watchClient.watchContractEvent({
      address: this.sessionManager,
      abi: SESSION_MANAGER_EVENTS,
      fromBlock,
      onLogs: (logs: any[]) => this.processLogs(logs),
    });

    const unwatchVerifier = this.watchClient.watchContractEvent({
      address: this.verifierRegistry,
      abi: VERIFIER_REGISTRY_EVENTS,
      fromBlock,
      onLogs: (logs: any[]) => this.processLogs(logs),
    });

    this.unwatchFns = [unwatchSession, unwatchVerifier];
  }

  async stop(): Promise<void> {
    for (const unwatch of this.unwatchFns) {
      try {
        unwatch();
      } catch {
        // ignore
      }
    }
    this.unwatchFns = [];
    this.started = false;
  }

  private async backfillFromCursor(): Promise<void> {
    const last = this.db.getChainCursor();
    const latest = await this.httpClient.getBlockNumber();

    const fromBlock = BigInt(last + 1);
    if (fromBlock > latest) return;

    const [sessionLogs, verifierLogs] = await Promise.all([
      this.httpClient.getLogs({
        address: this.sessionManager,
        events: SESSION_MANAGER_EVENTS as any,
        fromBlock,
        toBlock: latest,
      }) as Promise<any[]>,
      this.httpClient.getLogs({
        address: this.verifierRegistry,
        events: VERIFIER_REGISTRY_EVENTS as any,
        fromBlock,
        toBlock: latest,
      }) as Promise<any[]>,
    ]);

    const merged = [...sessionLogs, ...verifierLogs];
    merged.sort((a, b) => {
      const bnA = a.blockNumber as bigint;
      const bnB = b.blockNumber as bigint;
      if (bnA !== bnB) return bnA < bnB ? -1 : 1;
      const liA = a.logIndex as number;
      const liB = b.logIndex as number;
      return liA - liB;
    });

    await this.processLogs(merged);

    // We've scanned all blocks through `latest`, even if some had no logs.
    this.db.setChainCursor(toCursor(latest));
  }

  private async processLogs(logs: any[]): Promise<void> {
    if (!logs || logs.length === 0) return;

    let maxBlock = BigInt(this.db.getChainCursor());

    for (const l of logs) {
      const blockNumber = l.blockNumber as bigint;
      const eventName = l.eventName as keyof EventMap;

      const decoded: DecodedLog<any> = {
        address: l.address as Address,
        eventName: String(l.eventName ?? 'Unknown'),
        args: l.args ?? {},
        blockNumber,
        transactionHash: l.transactionHash as Hex,
        logIndex: l.logIndex as number,
      };

      await this.dispatch(eventName, decoded);

      if (blockNumber > maxBlock) maxBlock = blockNumber;
    }

    this.db.setChainCursor(toCursor(maxBlock));
  }

  private async dispatch<K extends keyof EventMap>(eventName: K, log: DecodedLog<EventMap[K]>): Promise<void> {
    const set = this.handlers[eventName];
    if (!set || set.size === 0) return;

    for (const h of set) {
      await h(log);
    }
  }
}
