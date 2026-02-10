import type { Address, Hex } from 'viem';

export type MigrationUrgency = 'emergency' | 'urgent' | 'routine';

export interface MigrationDecision {
  migrate: boolean;
  reason: string;
  urgency: MigrationUrgency;
  when: bigint; // epoch
}

export interface ShellAnomalyReport {
  level: MigrationUrgency | 'none';
  reasons: string[];
}

export interface MigrationPreferences {
  asset: Address;
  minAssuranceTier: number; // 0..3
  preferredAssuranceTier: number; // 0..3
  maxPricePerSU: bigint;
  priceIncreaseToleranceBps: number;
  requiredMaxSU: bigint;
  preferSameOperator: boolean;
  migrationBufferEpochs: bigint;
  tenureBufferEpochs: bigint;
  blacklistShellIds: Hex[];
}

export interface MigrationContext {
  nowEpoch: bigint;
  current: {
    shellId: Hex;
    operator?: string;
    pricePerSU: bigint;
    observedPricePerSU?: bigint;
    assuranceTier: number;
    leaseExpiryEpoch: bigint;
    residencyStartEpoch: bigint;
    tenureLimitEpochs: bigint;
  };
  anomalies: ShellAnomalyReport;
  preferences: MigrationPreferences;
}

export interface MigrationPlan {
  decision: MigrationDecision;
  primary: RankedDestination;
  fallbacks: RankedDestination[];
  migrateAtEpoch: bigint;
  estimatedBundleBytes: bigint;
}

// Part 3 spec, Section 13.1 (Offer discovery).
export interface Offer {
  offer_id: Hex;
  shell_id: Hex;
  chain_id: bigint;
  nonce: bigint;
  price_per_SU: bigint;
  escrow_asset: Address;
  min_lease: bigint;
  max_SU: bigint;
  assurance_tier: number;
  capability_hash: Hex;
  policy_tags: Hex;
  region: Hex;
  capacity: number;
  expiry: bigint;
}

export interface DiscoveredOffer {
  offer: Offer;
  signature: Hex;
  endpoint: string; // destination Shell HTTP base URL
  operator?: string;
}

export interface OfferFilters {
  minAssuranceTier: number;
  maxPricePerSU: bigint;
  asset: Address;
  minMaxSU: bigint;
  excludeShellIds: Hex[];
}

export interface RankedDestination {
  discovered: DiscoveredOffer;
  score: number;
}

export interface ShellRecord {
  shell_id: Hex;
  offer_signer_pubkey: Hex; // canonical pubkey bytes; may be an address-hex in tests
  bond_status: number; // 0=bonded
  certificate_id?: Hex;
  assurance_tier?: number;
}

export interface SessionState {
  shell_id: Hex;
  staging: boolean;
  pending_migration: boolean;
  mig_dest_shell_id: Hex;
  mig_dest_session_id: bigint;
  mig_expiry_epoch: bigint;
}

export interface ShellRegistryLike {
  getShell(shellId: Hex): Promise<ShellRecord>;
  assuranceTier(shellId: Hex): Promise<number>;
}

export interface SessionManagerLike {
  startMigration(ghostId: Hex, toShellId: Hex, bundleHash: Hex): Promise<void>;
  cancelMigration(ghostId: Hex): Promise<void>;
  finalizeMigration(ghostId: Hex, toShellId: Hex, proof: Hex): Promise<void>;
  getSession(ghostId: Hex): Promise<SessionState>;
}

export interface ReputationStore {
  getShellReputation(shellId: Hex): Promise<number>;
}

export type MigrationEvent = {
  type: string;
  atEpoch: bigint;
  data?: Record<string, unknown>;
};

export type MigrationHistoryEntry = {
  startedAtEpoch: bigint;
  destShellId: Hex;
  status: 'succeeded' | 'aborted' | 'failed';
  reason?: string;
};

export interface MigrationStore {
  getAttemptCount(ghostId: Hex): Promise<number>;
  incrementAttemptCount(ghostId: Hex): Promise<number>;
  recordEvent(ghostId: Hex, event: MigrationEvent): Promise<void>;
  recordHistory(ghostId: Hex, entry: MigrationHistoryEntry): Promise<void>;
}

export interface PackagerOpts {
  key: Uint8Array; // 32 bytes
  compression?: 'none' | 'gzip';
  hooks?: { flush(): Promise<void>; reload(): Promise<void> };
}

export interface MigrationBundle {
  encryptedState: Uint8Array;
  bundleHash: Hex;
  metadata: {
    compression: 'none' | 'gzip';
    format: 'json-files-v1';
    fileCount: number;
    plaintextBytes: number;
    compressedBytes: number;
  };
}

export interface ExecutorDeps {
  ghostId: Hex;
  sessionManager: SessionManagerLike;
  shellRegistry: ShellRegistryLike;

  offerDiscovery: {
    queryOffers(filters: OfferFilters): Promise<DiscoveredOffer[]>;
    rankOffers(offers: DiscoveredOffer[], ctx: MigrationContext): Promise<RankedDestination[]>;
  };

  planner: {
    shouldMigrate(ctx: MigrationContext): MigrationDecision;
    plan(
      decision: MigrationDecision,
      ranked: RankedDestination[],
      nowEpoch: bigint,
      estimatedBundleBytes: bigint,
    ): MigrationPlan;
  };

  statePackager: {
    package(agentDataDir: string, opts: PackagerOpts): Promise<MigrationBundle>;
    restore(bundle: MigrationBundle, agentDataDir: string, opts: PackagerOpts): Promise<void>;
    estimateBytes(agentDataDir: string): Promise<bigint>;
  };

  http: {
    postState(endpoint: string, bundle: MigrationBundle): Promise<{ bundleHash: Hex; proof: Hex }>;
  };

  hooks: { flush(): Promise<void>; reload(): Promise<void> };
  vault: { getKey(): Promise<Uint8Array> };
  checkpoint: { publishCheckpoint(): Promise<Hex>; distributeRecoveryShares(): Promise<void>; vaultState(): Promise<void> };
  heartbeat: { start(endpoint: string): Promise<void> };
  health: { check(endpoint: string): Promise<boolean> };
  store: MigrationStore;

  timing: { nowEpoch(): Promise<bigint>; sleepMs(ms: number): Promise<void> };
  limits: {
    maxMigrationAttempts: number;
    pollIntervalMs: number;
    stageOpenTimeoutMs: number;
    finalizeTimeoutMs: number;
  };
}
