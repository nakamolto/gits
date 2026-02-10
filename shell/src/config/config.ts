import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import * as TOML from '@iarna/toml';
import { isAddress, isHex, zeroHash } from 'viem';
import type { Address, Hex } from 'viem';

export type GasStrategy = 'auto' | 'fixed';
export type HeartbeatTransport = 'uds' | 'http' | 'both';

export interface PricingConfig {
  basePricePerSU: bigint;
  asset: Address;
  minLeaseEpochs: bigint;
  maxLeaseEpochs: bigint;
  dynamicPricing: boolean;
  premiumMultiplierBps: number;
}

export interface ShellConfig {
  identity: {
    shellId?: Hex;
    identityKeyPath: string;
    offerSignerKeyPath: string;
    recoveryKeyPath: string;
    payoutAddress: Address;
  };
  chain: {
    rpcUrl: string;
    chainId: bigint;
    deployment: {
      gitToken: Address;
      shellRegistry: Address;
      ghostRegistry: Address;
      sessionManager: Address;
      receiptManager: Address;
      rewardsManager: Address;
      verifierRegistry: Address;
    };
    gasStrategy: GasStrategy;
    maxGasPrice?: bigint;
  };
  offers: PricingConfig;
  compute: {
    maxConcurrentSessions: number;
    maxSUPerEpoch: number;
    heartbeatIntervalMs: number;
  };
  bond: {
    bondAsset: Address;
    bondAmount: bigint;
    safeHavenBondAmount: bigint;
  };
  storage: {
    dataDir: string;
  };
  tee?: {
    type: number;
    attestationEndpoint: string;
    measurementHash: Hex;
  };
  network: {
    listenPort: number;
    listenHost: string;
    heartbeatTransport: HeartbeatTransport;
    heartbeatSocketPath: string;
  };
  recovery?: {
    enabled: boolean;
    recoveryKeyPath: string;
  };
}

export function defaultShellConfigPath(): string {
  return path.join(os.homedir(), '.gits', 'shell.toml');
}

function expandHome(p: string): string {
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

function expectRecord(v: unknown, label: string): Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${label} must be a table/object`);
  return v as Record<string, unknown>;
}

function optString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function expectString(v: unknown, label: string): string {
  if (typeof v !== 'string' || v.length === 0) throw new Error(`${label} must be a non-empty string`);
  return v;
}

function expectNumber(v: unknown, label: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Error(`${label} must be a number`);
  return v;
}

function expectBoolean(v: unknown, label: string): boolean {
  if (typeof v !== 'boolean') throw new Error(`${label} must be a boolean`);
  return v;
}

function toBigInt(v: unknown, label: string): bigint {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isFinite(v) && Number.isInteger(v)) return BigInt(v);
  if (typeof v === 'string' && v.length > 0) {
    try {
      return BigInt(v);
    } catch {
      // fallthrough
    }
  }
  throw new Error(`${label} must be an integer (number, bigint, or string)`);
}

function expectAddress(v: unknown, label: string): Address {
  const s = expectString(v, label);
  if (!isAddress(s)) throw new Error(`${label} must be an EVM address`);
  return s as Address;
}

function expectHex32(v: unknown, label: string): Hex {
  const s = expectString(v, label);
  if (!isHex(s, { strict: true })) throw new Error(`${label} must be a hex string`);
  if (s.length !== 66) throw new Error(`${label} must be 32 bytes (0x + 64 hex chars)`);
  return s as Hex;
}

function optHex32(v: unknown): Hex | undefined {
  if (typeof v !== 'string') return undefined;
  if (!isHex(v, { strict: true })) return undefined;
  if (v.length !== 66) return undefined;
  return v as Hex;
}

function parseGasStrategy(v: unknown, label: string): GasStrategy {
  const s = expectString(v, label);
  if (s !== 'auto' && s !== 'fixed') throw new Error(`${label} must be 'auto' or 'fixed'`);
  return s;
}

function parseHeartbeatTransport(v: unknown, label: string): HeartbeatTransport {
  const s = expectString(v, label);
  if (s !== 'uds' && s !== 'http' && s !== 'both') throw new Error(`${label} must be 'uds', 'http', or 'both'`);
  return s;
}

function readDeployment(chainTable: Record<string, unknown>): ShellConfig['chain']['deployment'] {
  const depRaw = chainTable['deployment'];
  const dep = expectRecord(depRaw, 'chain.deployment');

  // Accept either camelCase or snake_case keys for compatibility.
  const pick = (camel: string, snake: string): unknown => (dep[camel] ?? dep[snake]);

  return {
    gitToken: expectAddress(pick('gitToken', 'git_token'), 'chain.deployment.gitToken'),
    shellRegistry: expectAddress(pick('shellRegistry', 'shell_registry'), 'chain.deployment.shellRegistry'),
    ghostRegistry: expectAddress(pick('ghostRegistry', 'ghost_registry'), 'chain.deployment.ghostRegistry'),
    sessionManager: expectAddress(pick('sessionManager', 'session_manager'), 'chain.deployment.sessionManager'),
    receiptManager: expectAddress(pick('receiptManager', 'receipt_manager'), 'chain.deployment.receiptManager'),
    rewardsManager: expectAddress(pick('rewardsManager', 'rewards_manager'), 'chain.deployment.rewardsManager'),
    verifierRegistry: expectAddress(pick('verifierRegistry', 'verifier_registry'), 'chain.deployment.verifierRegistry'),
  };
}

export async function loadShellConfig(configPath: string = defaultShellConfigPath()): Promise<ShellConfig> {
  const p = expandHome(configPath);
  const raw = await fs.readFile(p, 'utf8');
  const doc = TOML.parse(raw) as unknown;

  const root = expectRecord(doc, 'shell.toml');
  const identity = expectRecord(root['identity'], 'identity');
  const chain = expectRecord(root['chain'], 'chain');
  const offers = expectRecord(root['offers'], 'offers');
  const compute = expectRecord(root['compute'], 'compute');
  const bond = expectRecord(root['bond'], 'bond');
  const storage = expectRecord(root['storage'], 'storage');
  const network = expectRecord(root['network'], 'network');
  const teeRaw = root['tee'];
  const tee = teeRaw === undefined ? undefined : expectRecord(teeRaw, 'tee');
  const recoveryRaw = root['recovery'];
  const recovery = recoveryRaw === undefined ? undefined : expectRecord(recoveryRaw, 'recovery');

  const shellId = optHex32(identity['shellId'] ?? identity['shell_id']);

  const identityRecoveryKeyPath = expandHome(
    expectString(identity['recoveryKeyPath'] ?? identity['recovery_key_path'], 'identity.recoveryKeyPath'),
  );

  const dataDir = expandHome(expectString(storage['dataDir'] ?? storage['data_dir'], 'storage.dataDir'));

  const heartbeatSocketPath =
    expandHome(optString(network['heartbeatSocketPath'] ?? network['heartbeat_socket_path']) ?? '~/.gits/heartbeat.sock');

  const recoveryCfg: ShellConfig['recovery'] | undefined = recovery
    ? {
        enabled: expectBoolean(recovery['enabled'] ?? false, 'recovery.enabled'),
        recoveryKeyPath: expandHome(optString(recovery['recoveryKeyPath'] ?? recovery['recovery_key_path']) ?? identityRecoveryKeyPath),
      }
    : undefined;

  const cfg: ShellConfig = {
    identity: {
      shellId,
      identityKeyPath: expandHome(expectString(identity['identityKeyPath'] ?? identity['identity_key_path'], 'identity.identityKeyPath')),
      offerSignerKeyPath: expandHome(
        expectString(identity['offerSignerKeyPath'] ?? identity['offer_signer_key_path'], 'identity.offerSignerKeyPath'),
      ),
      recoveryKeyPath: identityRecoveryKeyPath,
      payoutAddress: expectAddress(identity['payoutAddress'] ?? identity['payout_address'], 'identity.payoutAddress'),
    },
    chain: {
      rpcUrl: expectString(chain['rpcUrl'] ?? chain['rpc_url'], 'chain.rpcUrl'),
      chainId: toBigInt(chain['chainId'] ?? chain['chain_id'], 'chain.chainId'),
      deployment: readDeployment(chain),
      gasStrategy: parseGasStrategy(chain['gasStrategy'] ?? chain['gas_strategy'] ?? 'auto', 'chain.gasStrategy'),
      maxGasPrice: chain['maxGasPrice'] ?? chain['max_gas_price'] ? toBigInt(chain['maxGasPrice'] ?? chain['max_gas_price'], 'chain.maxGasPrice') : undefined,
    },
    offers: {
      basePricePerSU: toBigInt(offers['basePricePerSU'] ?? offers['base_price_per_su'], 'offers.basePricePerSU'),
      asset: expectAddress(offers['asset'], 'offers.asset'),
      minLeaseEpochs: toBigInt(offers['minLeaseEpochs'] ?? offers['min_lease_epochs'], 'offers.minLeaseEpochs'),
      maxLeaseEpochs: toBigInt(offers['maxLeaseEpochs'] ?? offers['max_lease_epochs'], 'offers.maxLeaseEpochs'),
      dynamicPricing: expectBoolean(offers['dynamicPricing'] ?? offers['dynamic_pricing'] ?? false, 'offers.dynamicPricing'),
      premiumMultiplierBps: Number(expectNumber(offers['premiumMultiplierBps'] ?? offers['premium_multiplier_bps'] ?? 0, 'offers.premiumMultiplierBps')),
    },
    compute: {
      maxConcurrentSessions: Number(expectNumber(compute['maxConcurrentSessions'] ?? compute['max_concurrent_sessions'], 'compute.maxConcurrentSessions')),
      maxSUPerEpoch: Number(expectNumber(compute['maxSUPerEpoch'] ?? compute['max_su_per_epoch'], 'compute.maxSUPerEpoch')),
      heartbeatIntervalMs: Number(expectNumber(compute['heartbeatIntervalMs'] ?? compute['heartbeat_interval_ms'], 'compute.heartbeatIntervalMs')),
    },
    bond: {
      bondAsset: expectAddress(bond['bondAsset'] ?? bond['bond_asset'], 'bond.bondAsset'),
      bondAmount: toBigInt(bond['bondAmount'] ?? bond['bond_amount'], 'bond.bondAmount'),
      safeHavenBondAmount: toBigInt(bond['safeHavenBondAmount'] ?? bond['safe_haven_bond_amount'] ?? bond['safehaven_bond_amount'], 'bond.safeHavenBondAmount'),
    },
    storage: {
      dataDir,
    },
    tee: tee
      ? {
          type: Number(expectNumber(tee['type'], 'tee.type')),
          attestationEndpoint: expectString(tee['attestationEndpoint'] ?? tee['attestation_endpoint'], 'tee.attestationEndpoint'),
          measurementHash: expectHex32(tee['measurementHash'] ?? tee['measurement_hash'] ?? zeroHash, 'tee.measurementHash'),
        }
      : undefined,
    network: {
      listenPort: Number(expectNumber(network['listenPort'] ?? network['listen_port'], 'network.listenPort')),
      listenHost: optString(network['listenHost'] ?? network['listen_host']) ?? '127.0.0.1',
      heartbeatTransport: parseHeartbeatTransport(
        network['heartbeatTransport'] ?? network['heartbeat_transport'] ?? 'uds',
        'network.heartbeatTransport',
      ),
      heartbeatSocketPath,
    },
    recovery: recoveryCfg,
  };

  if (cfg.compute.maxConcurrentSessions <= 0) throw new Error('compute.maxConcurrentSessions must be > 0');
  if (cfg.compute.maxSUPerEpoch <= 0) throw new Error('compute.maxSUPerEpoch must be > 0');
  if (cfg.network.listenHost !== '127.0.0.1' && cfg.network.listenHost !== 'localhost') {
    throw new Error('network.listenHost must be 127.0.0.1 or localhost (Shell binds localhost-only)');
  }

  return cfg;
}
