import os from 'node:os';
import path from 'node:path';

import pino from 'pino';
import type { Logger } from 'pino';

import type { Address, Hex } from 'viem';
import { createPublicClient, http, webSocket, parseAbi, isHex } from 'viem';
import type { PublicClient } from 'viem';

import { GITSClient, EpochClock } from '@gits-protocol/sdk';

import type { GhostConfig } from './config/config.js';
import { DEFAULT_CONFIG_PATH, loadGhostConfig } from './config/config.js';
import type { IdentityKey } from './config/keys.js';
import { loadIdentityKey } from './config/keys.js';
import { GhostDB } from './storage/db.js';
import { GhostChainListener } from './chain/listener.js';
import { Metrics } from './telemetry/metrics.js';
import type { HealthStatus } from './telemetry/health.js';
import { HealthServer } from './telemetry/health.js';

export type GhostDaemonDeps = {
  loadConfig?: (configPath: string) => Promise<GhostConfig>;
  promptPassphrase?: (prompt: string) => Promise<string>;
  loadIdentityKey?: (identityKeyPath: string, passphrase: string) => Promise<IdentityKey>;
  openDb?: (dataDir: string) => Promise<GhostDB>;
  createSdkClient?: (deployment: GhostConfig['deployment']) => GITSClient;
  createPublicClient?: (httpRpcUrl: string) => PublicClient;
  createWatchClient?: (rpcUrl: string) => PublicClient | undefined;
  createEpochClock?: (genesisTime: bigint, epochLen: bigint) => EpochClock;
  createChainListener?: (args: {
    db: GhostDB;
    httpClient: PublicClient;
    watchClient?: PublicClient;
    sessionManager: Address;
    verifierRegistry: Address;
  }) => GhostChainListener;
  createHealthServer?: (args: { port: number; getStatus: () => HealthStatus }) => HealthServer;
};

export type DaemonModuleHooks = {
  onStart?: (ctx: DaemonContext) => void | Promise<void>;
  onStop?: (ctx: DaemonContext) => void | Promise<void>;
  onEpochTick?: (ctx: DaemonContext, epoch: bigint) => void | Promise<void>;
};

export type DaemonContext = {
  config: GhostConfig;
  logger: Logger;
  metrics: Metrics;
  db: GhostDB;
  sdk: GITSClient;
  publicClient: PublicClient;
  chainListener: GhostChainListener;
  epochClock: EpochClock;
  identity: IdentityKey;
};

type ModuleState = {
  name: string;
  hooks: DaemonModuleHooks;
  started: boolean;
  lastEpochTick?: bigint;
};

const GHOST_REGISTRY_ABI = parseAbi([
  'function getGhost(bytes32 ghost_id) view returns ((bytes32, bytes, address, (bytes32[], uint64, address, uint256, uint256), bytes32, bytes32, bytes, bytes, uint256, uint256, address, uint256, uint256))',
]);

const SESSION_MANAGER_VIEWS_ABI = parseAbi([
  'function GENESIS_TIME() view returns (uint256)',
  'function EPOCH_LEN() view returns (uint256)',
  'function getSession(bytes32 ghost_id) view returns ((uint256, bytes32, bytes32, uint8, uint8, uint256, uint256, uint256, uint256, uint256, uint8, uint8, bool, bool, bool, bytes32, uint256, uint256))',
]);

function deriveHttpUrl(rpcUrl: string): string {
  if (rpcUrl.startsWith('ws://')) return 'http://' + rpcUrl.slice('ws://'.length);
  if (rpcUrl.startsWith('wss://')) return 'https://' + rpcUrl.slice('wss://'.length);
  return rpcUrl;
}

function deriveWsUrl(rpcUrl: string): string | undefined {
  if (rpcUrl.startsWith('http://')) return 'ws://' + rpcUrl.slice('http://'.length);
  if (rpcUrl.startsWith('https://')) return 'wss://' + rpcUrl.slice('https://'.length);
  if (rpcUrl.startsWith('ws://') || rpcUrl.startsWith('wss://')) return rpcUrl;
  return undefined;
}

async function promptHidden(prompt: string): Promise<string> {
  // Basic TTY prompt without adding deps; falls back to empty string.
  if (!process.stdin.isTTY) return '';

  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });

  const onData = () => {
    // Redraw prompt + masked input.
    const masked = '*'.repeat(rl.line.length);
    (process.stdout as any).clearLine?.(0);
    (process.stdout as any).cursorTo?.(0);
    process.stdout.write(prompt + masked);
  };

  process.stdin.on('data', onData);

  try {
    return await new Promise<string>((resolve) => {
      rl.question(prompt, (answer) => {
        rl.close();
        process.stdout.write('\n');
        resolve(answer);
      });
    });
  } finally {
    process.stdin.off('data', onData);
  }
}

export class GhostDaemon {
  private modules: ModuleState[] = [];
  private readonly deps: GhostDaemonDeps;

  private configPath: string;
  private config?: GhostConfig;
  private logger?: Logger;
  private metrics = new Metrics();

  private db?: GhostDB;
  private sdk?: GITSClient;
  private publicClient?: PublicClient;
  private chainListener?: GhostChainListener;
  private epochClock?: EpochClock;
  private identity?: IdentityKey;

  private epochTimer?: NodeJS.Timeout;
  private healthServer?: HealthServer;

  private ready = false;
  private warnings: string[] = [];

  constructor(args?: { configPath?: string; logger?: Logger; deps?: GhostDaemonDeps }) {
    this.configPath = args?.configPath ?? DEFAULT_CONFIG_PATH;
    this.logger = args?.logger;
    this.deps = args?.deps ?? {};
  }

  registerModule(name: string, hooks: DaemonModuleHooks): void {
    if (this.modules.find((m) => m.name === name)) throw new Error(`GhostDaemon: module already registered: ${name}`);
    this.modules.push({ name, hooks, started: false });
  }

  async start(args?: { identityPassphrase?: string }): Promise<void> {
    if (this.ready) return;

    this.config = await (this.deps.loadConfig ?? loadGhostConfig)(this.configPath);

    this.logger = this.logger ?? pino({ level: this.config.telemetry.logLevel });
    this.logger.info({ configPath: this.configPath }, 'Loading Ghost config');

    const passphrase =
      args?.identityPassphrase ??
      process.env.GITS_GHOST_PASSPHRASE ??
      (await (this.deps.promptPassphrase ?? promptHidden)('Ghost identity key passphrase: '));

    if (!passphrase) throw new Error('GhostDaemon: missing identity key passphrase');

    this.identity = await (this.deps.loadIdentityKey ?? loadIdentityKey)(this.config.identityKeyPath, passphrase);

    this.db = await (this.deps.openDb ?? GhostDB.open)(this.config.dataDir);

    this.sdk = (this.deps.createSdkClient ?? ((d) => new GITSClient(d)))(this.config.deployment);

    const httpUrl = deriveHttpUrl(this.config.rpcUrl);
    const wsUrl = deriveWsUrl(this.config.rpcUrl);

    this.publicClient = (this.deps.createPublicClient ?? ((url) => createPublicClient({ transport: http(url) })))(httpUrl);

    const watchClient = (this.deps.createWatchClient ??
      ((rpcUrl) => {
        const ws = deriveWsUrl(rpcUrl);
        return ws ? createPublicClient({ transport: webSocket(ws) }) : undefined;
      }))(wsUrl ?? this.config.rpcUrl);

    // Verify registration.
    await this.verifyOnChainRegistration();

    // Epoch clock from on-chain constants.
    const genesis = (await this.publicClient.readContract({
      address: this.config.deployment.session_manager,
      abi: SESSION_MANAGER_VIEWS_ABI,
      functionName: 'GENESIS_TIME',
    })) as bigint;

    const epochLen = (await this.publicClient.readContract({
      address: this.config.deployment.session_manager,
      abi: SESSION_MANAGER_VIEWS_ABI,
      functionName: 'EPOCH_LEN',
    })) as bigint;

    this.epochClock = (this.deps.createEpochClock ?? ((g, e) => new EpochClock(g, e)))(genesis, epochLen);

    this.chainListener = (this.deps.createChainListener ?? ((a) => new GhostChainListener(a)))({
      db: this.db,
      httpClient: this.publicClient,
      watchClient,
      sessionManager: this.config.deployment.session_manager,
      verifierRegistry: this.config.deployment.verifier_registry,
    });

    await this.chainListener.start();

    // Crash recovery hints.
    this.detectStrandedSessions();

    // Start modules.
    const ctx = this.getContext();
    for (const m of this.modules) {
      if (m.hooks.onStart) await m.hooks.onStart(ctx);
      m.started = true;
    }

    if (this.config.telemetry.healthPort != null) {
      this.healthServer = (this.deps.createHealthServer ?? ((a) => new HealthServer(a)))({
        port: this.config.telemetry.healthPort,
        getStatus: () => this.status(),
      });
      await this.healthServer.start();
    }

    this.ready = true;

    const mode = await this.tryGetMode();
    this.logger.info({ ghost_id: this.config.ghostId, mode }, 'Ghost daemon ready');

    this.scheduleNextEpochTick();
  }

  async stop(): Promise<void> {
    if (!this.ready) return;

    if (this.epochTimer) clearTimeout(this.epochTimer);
    this.epochTimer = undefined;

    const ctx = this.getContext();

    // Stop modules in reverse registration order.
    for (const m of [...this.modules].reverse()) {
      try {
        if (m.started && m.hooks.onStop) await m.hooks.onStop(ctx);
      } finally {
        m.started = false;
      }
    }

    if (this.chainListener) await this.chainListener.stop();
    if (this.healthServer) await this.healthServer.stop();
    if (this.db) this.db.close();

    this.ready = false;
  }

  status(): HealthStatus {
    const last_block = this.db?.getChainCursor();

    const modules: HealthStatus['modules'] = {};
    for (const m of this.modules) {
      modules[m.name] = {
        started: m.started,
        lastEpochTick: m.lastEpochTick != null ? m.lastEpochTick.toString() : undefined,
      };
    }

    return {
      ok: true,
      ready: this.ready,
      ghost_id: this.config?.ghostId,
      epoch: this.epochClock?.currentEpoch().toString(),
      last_block,
      warnings: [...this.warnings],
      modules,
    };
  }

  private getContext(): DaemonContext {
    if (!this.config || !this.logger || !this.db || !this.sdk || !this.publicClient || !this.chainListener || !this.epochClock || !this.identity) {
      throw new Error('GhostDaemon: not initialized');
    }

    return {
      config: this.config,
      logger: this.logger,
      metrics: this.metrics,
      db: this.db,
      sdk: this.sdk,
      publicClient: this.publicClient,
      chainListener: this.chainListener,
      epochClock: this.epochClock,
      identity: this.identity,
    };
  }

  private async verifyOnChainRegistration(): Promise<void> {
    if (!this.config || !this.publicClient || !this.identity) throw new Error('GhostDaemon: not initialized');

    const record = (await this.publicClient.readContract({
      address: this.config.deployment.ghost_registry,
      abi: GHOST_REGISTRY_ABI,
      functionName: 'getGhost',
      args: [this.config.ghostId],
    })) as any;

    const wallet = (record.wallet ?? record[2]) as Address;
    if (wallet.toLowerCase() !== this.config.walletAddress.toLowerCase()) {
      throw new Error(`GhostDaemon: on-chain wallet mismatch (expected ${this.config.walletAddress}, got ${wallet})`);
    }

    const identity_pubkey = (record.identity_pubkey ?? record[1]) as Hex;
    if (!isHex(identity_pubkey)) throw new Error('GhostDaemon: invalid on-chain identity_pubkey');

    if (identity_pubkey.toLowerCase() !== this.identity.identityPubkeyBytes.toLowerCase()) {
      throw new Error('GhostDaemon: on-chain identity key does not match local identity key');
    }

    // Bond sanity check (not enforced here, but logged).
    const bond_asset = (record.bond_asset ?? record[10]) as Address;
    const bond_amount = (record.bond_amount ?? record[11]) as bigint;

    this.logger?.info(
      {
        bond_asset,
        bond_amount: bond_amount?.toString?.() ?? String(bond_amount),
      },
      'Verified Ghost registration',
    );
  }

  private detectStrandedSessions(): void {
    if (!this.db) return;

    const open = this.db.listSessions().filter((s) => s.status !== 'closed' && s.status !== 'settled');
    if (open.length === 0) return;

    this.warnings.push(`Detected ${open.length} non-closed sessions in local DB (recovery may be required)`);
  }

  private scheduleNextEpochTick(): void {
    if (!this.epochClock) return;
    const remainingSec = this.epochClock.secondsRemaining();

    // Fire shortly after the boundary.
    const ms = Math.max(250, Number(remainingSec) * 1000 + 250);
    this.epochTimer = setTimeout(() => void this.handleEpochTick(), ms);
  }

  private async handleEpochTick(): Promise<void> {
    if (!this.ready || !this.epochClock) return;

    const epoch = this.epochClock.currentEpoch();

    try {
      const ctx = this.getContext();
      for (const m of this.modules) {
        if (!m.started || !m.hooks.onEpochTick) continue;
        await m.hooks.onEpochTick(ctx, epoch);
        m.lastEpochTick = epoch;
      }
    } finally {
      this.scheduleNextEpochTick();
    }
  }

  private async tryGetMode(): Promise<string> {
    if (!this.publicClient || !this.config) return 'unknown';

    try {
      const s = (await this.publicClient.readContract({
        address: this.config.deployment.session_manager,
        abi: SESSION_MANAGER_VIEWS_ABI,
        functionName: 'getSession',
        args: [this.config.ghostId],
      })) as any;

      const mode = (s.mode ?? s[3]) as bigint;
      return mode != null ? mode.toString() : 'unknown';
    } catch {
      return 'unknown';
    }
  }
}

export function defaultDataDir(): string {
  return path.join(os.homedir(), '.gits', 'ghost');
}
