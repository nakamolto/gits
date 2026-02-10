import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';

import type { Address, Hex } from 'viem';
import { isAddress, isHex } from 'viem';
import type { GITSDeployment } from '@gits-protocol/sdk';

// `smol-toml` is intentionally tiny and pure JS (no native deps).
import * as smolToml from 'smol-toml';

export type MigrationPolicy = {
  enabled: boolean;
  triggers: {
    missedHeartbeats: boolean;
    verifierSlash: boolean;
    measurementRevoked: boolean;
  };
  preferences: {
    preferTrustedShells: boolean;
    maxPricePerSU?: bigint;
    minAssuranceTier?: number;
  };
  timing: {
    maxDelayEpochs: bigint;
    cooldownEpochs: bigint;
  };
};

export type VaultingConfig = {
  enabled: boolean;
  checkpointIntervalEpochs: bigint;
  shamir: { t: number; n: number };
  encryption: { kdf: 'scrypt'; saltBytes: number };
};

export type RecoveryPreferences = {
  recoverySetShellIds: Hex[];
  threshold: number;
  bounty: {
    asset: Address;
    total: bigint;
    bpsInitiator: bigint;
  };
};

export type GhostConfig = {
  // Identity
  ghostId: Hex;
  identityKeyPath: string;
  walletAddress: Address;

  // Chain
  rpcUrl: string;
  chainId: bigint;
  deployment: GITSDeployment;

  // Session preferences
  maxPricePerSU: bigint;
  preferredAssuranceTier: number;
  minAssuranceTier: number;
  preferredLeaseEpochs: bigint;
  autoRenewLease: boolean;

  // Migration/Vaulting/Recovery
  migration: MigrationPolicy;
  vaulting: VaultingConfig;
  recovery: RecoveryPreferences;

  // Agent integration
  agentRuntime: 'openclaw' | 'generic';
  agentDataDir: string;
  agentSocketPath: string;

  // Storage
  dataDir: string;

  // Telemetry
  telemetry: {
    logLevel: 'debug' | 'info' | 'warn' | 'error';
    healthPort?: number;
  };
};

export const DEFAULT_CONFIG_PATH = path.join(os.homedir(), '.gits', 'ghost.toml');

function expandHome(p: string): string {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2));
  return p;
}

function asString(v: unknown, field: string): string {
  if (typeof v !== 'string' || !v) throw new Error(`Config: missing/invalid ${field}`);
  return v;
}

function asOptionalString(v: unknown): string | undefined {
  if (v == null) return undefined;
  if (typeof v !== 'string') return undefined;
  return v;
}

function asBoolean(v: unknown, field: string, defaultValue: boolean): boolean {
  if (v == null) return defaultValue;
  if (typeof v !== 'boolean') throw new Error(`Config: invalid ${field} (expected boolean)`);
  return v;
}

function asNumber(v: unknown, field: string, defaultValue?: number): number {
  if (v == null) {
    if (defaultValue == null) throw new Error(`Config: missing ${field}`);
    return defaultValue;
  }
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Error(`Config: invalid ${field} (expected number)`);
  return v;
}

function asBigInt(v: unknown, field: string, defaultValue?: bigint): bigint {
  if (v == null) {
    if (defaultValue == null) throw new Error(`Config: missing ${field}`);
    return defaultValue;
  }
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error(`Config: invalid ${field} (expected integer)`);
    return BigInt(v);
  }
  if (typeof v === 'string') {
    if (!v) throw new Error(`Config: invalid ${field} (empty)`);
    return BigInt(v);
  }
  throw new Error(`Config: invalid ${field} (expected bigint-compatible)`);
}

function asHex32(v: unknown, field: string): Hex {
  const s = asString(v, field);
  if (!isHex(s)) throw new Error(`Config: invalid ${field} (not hex)`);
  if (s.length !== 66) throw new Error(`Config: invalid ${field} (expected 32-byte hex)`);
  return s as Hex;
}

function asAddress(v: unknown, field: string): Address {
  const s = asString(v, field);
  if (!isAddress(s)) throw new Error(`Config: invalid ${field} (not an address)`);
  return s as Address;
}

function asLogLevel(v: unknown): 'debug' | 'info' | 'warn' | 'error' {
  if (v == null) return 'info';
  if (v === 'debug' || v === 'info' || v === 'warn' || v === 'error') return v;
  throw new Error('Config: invalid telemetry.logLevel');
}

function asArray(v: unknown): unknown[] {
  if (v == null) return [];
  if (!Array.isArray(v)) throw new Error('Config: expected array');
  return v;
}

function normalizeDeployment(v: unknown): GITSDeployment {
  if (!v || typeof v !== 'object') throw new Error('Config: missing deployment');
  const d = v as any;

  const chain_id = asBigInt(d.chain_id, 'deployment.chain_id');

  const addr = (x: unknown, field: string) => asAddress(x, field);

  return {
    chain_id,
    git_token: addr(d.git_token, 'deployment.git_token'),
    shell_registry: addr(d.shell_registry, 'deployment.shell_registry'),
    ghost_registry: addr(d.ghost_registry, 'deployment.ghost_registry'),
    session_manager: addr(d.session_manager, 'deployment.session_manager'),
    receipt_manager: addr(d.receipt_manager, 'deployment.receipt_manager'),
    rewards_manager: addr(d.rewards_manager, 'deployment.rewards_manager'),
    verifier_registry: addr(d.verifier_registry, 'deployment.verifier_registry'),
  };
}

function normalizeConfig(raw: any): GhostConfig {
  const dataDir = expandHome(asOptionalString(raw.dataDir) ?? path.join(os.homedir(), '.gits', 'ghost'));

  const ghostId = asHex32(raw.ghostId ?? raw.ghost_id, 'ghostId');
  const walletAddress = asAddress(raw.walletAddress ?? raw.wallet_address, 'walletAddress');

  const deployment = normalizeDeployment(raw.deployment);

  const rpcUrl = asString(raw.rpcUrl ?? raw.rpc_url, 'rpcUrl');
  const chainId = asBigInt(raw.chainId ?? raw.chain_id, 'chainId', deployment.chain_id);

  const identityKeyPath = expandHome(
    asOptionalString(raw.identityKeyPath ?? raw.identity_key_path) ?? path.join(dataDir, 'identity.key'),
  );

  const maxPricePerSU = asBigInt(raw.maxPricePerSU ?? raw.max_price_per_su, 'maxPricePerSU', 0n);
  const preferredAssuranceTier = asNumber(
    raw.preferredAssuranceTier ?? raw.preferred_assurance_tier,
    'preferredAssuranceTier',
    0,
  );
  const minAssuranceTier = asNumber(raw.minAssuranceTier ?? raw.min_assurance_tier, 'minAssuranceTier', 0);
  const preferredLeaseEpochs = asBigInt(
    raw.preferredLeaseEpochs ?? raw.preferred_lease_epochs,
    'preferredLeaseEpochs',
    1n,
  );
  const autoRenewLease = asBoolean(raw.autoRenewLease ?? raw.auto_renew_lease, 'autoRenewLease', false);

  if (minAssuranceTier > preferredAssuranceTier) {
    throw new Error('Config: minAssuranceTier must be <= preferredAssuranceTier');
  }

  const migrationRaw = raw.migration ?? {};
  const migration: MigrationPolicy = {
    enabled: asBoolean(migrationRaw.enabled, 'migration.enabled', false),
    triggers: {
      missedHeartbeats: asBoolean(migrationRaw.triggers?.missedHeartbeats, 'migration.triggers.missedHeartbeats', false),
      verifierSlash: asBoolean(migrationRaw.triggers?.verifierSlash, 'migration.triggers.verifierSlash', false),
      measurementRevoked: asBoolean(
        migrationRaw.triggers?.measurementRevoked,
        'migration.triggers.measurementRevoked',
        false,
      ),
    },
    preferences: {
      preferTrustedShells: asBoolean(
        migrationRaw.preferences?.preferTrustedShells,
        'migration.preferences.preferTrustedShells',
        true,
      ),
      maxPricePerSU:
        migrationRaw.preferences?.maxPricePerSU != null
          ? asBigInt(migrationRaw.preferences.maxPricePerSU, 'migration.preferences.maxPricePerSU')
          : undefined,
      minAssuranceTier:
        migrationRaw.preferences?.minAssuranceTier != null
          ? asNumber(migrationRaw.preferences.minAssuranceTier, 'migration.preferences.minAssuranceTier')
          : undefined,
    },
    timing: {
      maxDelayEpochs: asBigInt(migrationRaw.timing?.maxDelayEpochs, 'migration.timing.maxDelayEpochs', 0n),
      cooldownEpochs: asBigInt(migrationRaw.timing?.cooldownEpochs, 'migration.timing.cooldownEpochs', 0n),
    },
  };

  const vaultingRaw = raw.vaulting ?? {};
  const shamirT = asNumber(vaultingRaw.shamir?.t, 'vaulting.shamir.t', 2);
  const shamirN = asNumber(vaultingRaw.shamir?.n, 'vaulting.shamir.n', 3);
  if (shamirT < 1 || shamirN < 1 || shamirT > shamirN) throw new Error('Config: invalid vaulting.shamir t/n');

  const vaulting: VaultingConfig = {
    enabled: asBoolean(vaultingRaw.enabled, 'vaulting.enabled', false),
    checkpointIntervalEpochs: asBigInt(vaultingRaw.checkpointIntervalEpochs, 'vaulting.checkpointIntervalEpochs', 1n),
    shamir: { t: shamirT, n: shamirN },
    encryption: {
      kdf: 'scrypt',
      saltBytes: asNumber(vaultingRaw.encryption?.saltBytes, 'vaulting.encryption.saltBytes', 16),
    },
  };

  const recoveryRaw = raw.recovery ?? {};
  const recoverySet = asArray(recoveryRaw.recoverySetShellIds ?? recoveryRaw.recovery_set_shell_ids).map((x) =>
    asHex32(x, 'recovery.recoverySetShellIds'),
  );

  const recovery: RecoveryPreferences = {
    recoverySetShellIds: recoverySet as Hex[],
    threshold: asNumber(recoveryRaw.threshold, 'recovery.threshold', 0),
    bounty: {
      asset: asAddress(recoveryRaw.bounty?.asset ?? '0x0000000000000000000000000000000000000000', 'recovery.bounty.asset'),
      total: asBigInt(recoveryRaw.bounty?.total, 'recovery.bounty.total', 0n),
      bpsInitiator: asBigInt(recoveryRaw.bounty?.bpsInitiator, 'recovery.bounty.bpsInitiator', 0n),
    },
  };

  const agentRuntime = (raw.agentRuntime ?? raw.agent_runtime ?? 'generic') as any;
  if (agentRuntime !== 'openclaw' && agentRuntime !== 'generic') throw new Error('Config: invalid agentRuntime');

  const agentDataDir = expandHome(
    asOptionalString(raw.agentDataDir ?? raw.agent_data_dir) ?? path.join(dataDir, 'agent'),
  );
  const agentSocketPath = expandHome(
    asOptionalString(raw.agentSocketPath ?? raw.agent_socket_path) ?? path.join(dataDir, 'agent.sock'),
  );

  const telemetryRaw = raw.telemetry ?? {};
  const telemetry: GhostConfig['telemetry'] = {
    logLevel: asLogLevel(telemetryRaw.logLevel ?? telemetryRaw.log_level),
    healthPort:
      telemetryRaw.healthPort != null
        ? asNumber(telemetryRaw.healthPort, 'telemetry.healthPort')
        : telemetryRaw.health_port != null
          ? asNumber(telemetryRaw.health_port, 'telemetry.healthPort')
          : undefined,
  };

  return {
    ghostId,
    identityKeyPath,
    walletAddress,
    rpcUrl,
    chainId,
    deployment,
    maxPricePerSU,
    preferredAssuranceTier,
    minAssuranceTier,
    preferredLeaseEpochs,
    autoRenewLease,
    migration,
    vaulting,
    recovery,
    agentRuntime,
    agentDataDir,
    agentSocketPath,
    dataDir,
    telemetry,
  };
}

export async function loadGhostConfig(configPath: string = DEFAULT_CONFIG_PATH): Promise<GhostConfig> {
  const p = expandHome(configPath);
  const rawText = await fs.readFile(p, 'utf8');

  let raw: any;
  const ext = path.extname(p).toLowerCase();

  if (ext === '.json') {
    raw = JSON.parse(rawText);
  } else {
    // Try TOML first; if it fails, try JSON as a fallback.
    try {
      // `smol-toml` exports a `parse` function.
      raw = (smolToml as any).parse(rawText);
    } catch (errToml) {
      try {
        raw = JSON.parse(rawText);
      } catch {
        const msg = errToml instanceof Error ? errToml.message : String(errToml);
        throw new Error(`Config: failed to parse TOML (and JSON fallback failed): ${msg}`);
      }
    }
  }

  return normalizeConfig(raw);
}
