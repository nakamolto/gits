import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import type { Address, Hex } from 'viem';

import { MigrationExecutor } from '../src/migration/executor.js';
import { rankOffers } from '../src/migration/offer-discovery.js';
import { plan as planFn, scoreOffer, shouldMigrate } from '../src/migration/planner.js';
import { BundleHashMismatchError } from '../src/migration/state-packager.js';
import { package as packageState, restore as restoreState } from '../src/migration/state-packager.js';
import type {
  DiscoveredOffer,
  MigrationBundle,
  MigrationContext,
  MigrationDecision,
  MigrationPlan,
  Offer,
  RankedDestination,
  SessionState,
} from '../src/migration/types.js';

const ZERO32 = ('0x' + '00'.repeat(32)) as Hex;

function hex32(byte: string) {
  return ('0x' + byte.repeat(32)) as Hex;
}

function addr(byte: string) {
  return ('0x' + byte.repeat(20)) as Address;
}

function baseCtx(): MigrationContext {
  return {
    nowEpoch: 100n,
    current: {
      shellId: hex32('11'),
      operator: 'opA',
      pricePerSU: 100n,
      observedPricePerSU: 100n,
      assuranceTier: 3,
      leaseExpiryEpoch: 200n,
      residencyStartEpoch: 50n,
      tenureLimitEpochs: 200n,
    },
    anomalies: { level: 'none', reasons: [] },
    preferences: {
      asset: addr('aa'),
      minAssuranceTier: 2,
      preferredAssuranceTier: 3,
      maxPricePerSU: 150n,
      priceIncreaseToleranceBps: 500,
      requiredMaxSU: 10n,
      preferSameOperator: true,
      migrationBufferEpochs: 5n,
      tenureBufferEpochs: 5n,
      blacklistShellIds: [],
    },
  };
}

function offerTemplate(overrides?: Partial<Offer>): Offer {
  return {
    offer_id: hex32('01'),
    shell_id: hex32('22'),
    chain_id: 1n,
    nonce: 1n,
    price_per_SU: 100n,
    escrow_asset: addr('aa'),
    min_lease: 1n,
    max_SU: 10n,
    assurance_tier: 3,
    capability_hash: hex32('03'),
    policy_tags: '0x',
    region: hex32('04'),
    capacity: 1,
    expiry: 0n,
    ...overrides,
  };
}

describe('planner.shouldMigrate', () => {
  it('migrates immediately on emergency anomaly', () => {
    const ctx = baseCtx();
    ctx.anomalies = { level: 'emergency', reasons: ['kernel panic'] };
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.urgency).toBe('emergency');
    expect(d.when).toBe(100n);
    expect(d.reason).toContain('kernel panic');
  });

  it('migrates urgently when lease within buffer', () => {
    const ctx = baseCtx();
    ctx.current.leaseExpiryEpoch = 105n;
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.urgency).toBe('urgent');
    expect(d.when).toBe(100n);
  });

  it('migrates routinely when tenure within buffer', () => {
    const ctx = baseCtx();
    ctx.nowEpoch = 95n;
    ctx.current.residencyStartEpoch = 90n;
    ctx.current.tenureLimitEpochs = 10n; // end=100
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.urgency).toBe('routine');
  });

  it('migrates routinely when AT below preferred', () => {
    const ctx = baseCtx();
    ctx.current.assuranceTier = 2;
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.urgency).toBe('routine');
    expect(d.when).toBe(101n);
  });

  it('migrates routinely when price above maximum', () => {
    const ctx = baseCtx();
    ctx.current.observedPricePerSU = 999n;
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.reason).toContain('price');
  });

  it('migrates routinely when price increases beyond tolerance', () => {
    const ctx = baseCtx();
    ctx.current.pricePerSU = 100n; // baseline
    ctx.current.observedPricePerSU = 106n; // +6%
    ctx.preferences.maxPricePerSU = 1000n; // not the trigger
    ctx.preferences.priceIncreaseToleranceBps = 500; // 5%
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(true);
    expect(d.reason).toContain('tolerance');
  });

  it('does not migrate with no triggers', () => {
    const ctx = baseCtx();
    const d = shouldMigrate(ctx);
    expect(d.migrate).toBe(false);
  });
});

describe('planner.scoreOffer', () => {
  it('rejects offers that violate hard constraints', () => {
    const ctx = baseCtx();
    const discovered: DiscoveredOffer = { offer: offerTemplate(), signature: '0x' as Hex, endpoint: 'http://x' };

    expect(
      scoreOffer({
        discovered: { ...discovered, offer: { ...discovered.offer, escrow_asset: addr('bb') } },
        context: ctx,
        reputation: 0,
      }),
    ).toBe(Number.NEGATIVE_INFINITY);

    expect(
      scoreOffer({
        discovered: { ...discovered, offer: { ...discovered.offer, price_per_SU: 999n } },
        context: ctx,
        reputation: 0,
      }),
    ).toBe(Number.NEGATIVE_INFINITY);

    expect(
      scoreOffer({
        discovered: { ...discovered, offer: { ...discovered.offer, assurance_tier: 1 } },
        context: ctx,
        reputation: 0,
      }),
    ).toBe(Number.NEGATIVE_INFINITY);

    expect(
      scoreOffer({
        discovered: { ...discovered, offer: { ...discovered.offer, max_SU: 1n } },
        context: ctx,
        reputation: 0,
      }),
    ).toBe(Number.NEGATIVE_INFINITY);
  });

  it('prefers lower price and higher assurance tier', () => {
    const ctx = baseCtx();
    const base: DiscoveredOffer = { offer: offerTemplate(), signature: '0x' as Hex, endpoint: 'http://x' };

    const lowPrice = scoreOffer({
      discovered: { ...base, offer: { ...base.offer, price_per_SU: 50n } },
      context: ctx,
      reputation: 0,
    });
    const highPrice = scoreOffer({
      discovered: { ...base, offer: { ...base.offer, price_per_SU: 100n } },
      context: ctx,
      reputation: 0,
    });
    expect(lowPrice).toBeGreaterThan(highPrice);

    const at2 = scoreOffer({
      discovered: { ...base, offer: { ...base.offer, assurance_tier: 2 } },
      context: ctx,
      reputation: 0,
    });
    const at3 = scoreOffer({
      discovered: { ...base, offer: { ...base.offer, assurance_tier: 3 } },
      context: ctx,
      reputation: 0,
    });
    expect(at3).toBeGreaterThan(at2);
  });

  it('applies operator and reputation bonuses', () => {
    const ctx = baseCtx();
    const base: DiscoveredOffer = {
      offer: offerTemplate(),
      signature: '0x' as Hex,
      endpoint: 'http://x',
      operator: 'opA',
    };

    const withBonuses = scoreOffer({ discovered: base, context: ctx, reputation: 10 });
    const withoutBonuses = scoreOffer({ discovered: { ...base, operator: 'other' }, context: ctx, reputation: 0 });
    expect(withBonuses).toBeGreaterThan(withoutBonuses);
  });
});

describe('offer-discovery.rankOffers', () => {
  it('verifies + ranks offers by score', async () => {
    const ctx = baseCtx();
    ctx.preferences.maxPricePerSU = 200n;

    const shellRegistryAddress = addr('cc');
    const account = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);

    const types = {
      Offer: [
        { name: 'offer_id', type: 'bytes32' },
        { name: 'shell_id', type: 'bytes32' },
        { name: 'chain_id', type: 'uint256' },
        { name: 'nonce', type: 'uint64' },
        { name: 'price_per_SU', type: 'uint256' },
        { name: 'escrow_asset', type: 'address' },
        { name: 'min_lease', type: 'uint64' },
        { name: 'max_SU', type: 'uint64' },
        { name: 'assurance_tier', type: 'uint8' },
        { name: 'capability_hash', type: 'bytes32' },
        { name: 'policy_tags', type: 'bytes' },
        { name: 'region', type: 'bytes32' },
        { name: 'capacity', type: 'uint32' },
        { name: 'expiry', type: 'uint64' },
      ],
    } as const;

    function domain(chainId: bigint): any {
      return { name: 'GITSOffer', version: '1', chainId: Number(chainId), verifyingContract: shellRegistryAddress };
    }

    const offerA = offerTemplate({ offer_id: hex32('0a'), shell_id: hex32('aa'), price_per_SU: 50n });
    const sigA = await account.signTypedData({
      domain: domain(offerA.chain_id),
      types,
      primaryType: 'Offer',
      message: offerA,
    });

    const offerB = offerTemplate({ offer_id: hex32('0b'), shell_id: hex32('bb'), price_per_SU: 120n });
    const sigB = await account.signTypedData({
      domain: domain(offerB.chain_id),
      types,
      primaryType: 'Offer',
      message: offerB,
    });

    const offers: DiscoveredOffer[] = [
      { offer: offerB, signature: sigB, endpoint: 'http://b', operator: 'opB' },
      { offer: offerA, signature: sigA, endpoint: 'http://a', operator: 'opA' },
    ];

    const shellRegistry = {
      getShell: async (shellId: Hex) => ({
        shell_id: shellId,
        offer_signer_pubkey: account.address as unknown as Hex,
        bond_status: 0,
      }),
      assuranceTier: async () => 3,
    };

    const reputationStore = { getShellReputation: async () => 0 };

    const ranked = await rankOffers(offers, ctx, {
      shellRegistry,
      shellRegistryAddress,
      reputationStore,
    });

    expect(ranked.length).toBe(2);
    expect(ranked[0].discovered.offer.offer_id).toBe(offerA.offer_id);
    expect(ranked[0].score).toBeGreaterThan(ranked[1].score);
  });
});

describe('state-packager', () => {
  it('encrypt/decrypt roundtrip (gzip) and hash verification', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-pack-'));
    const src = path.join(tmp, 'src');
    const dst = path.join(tmp, 'dst');
    await fs.mkdir(path.join(src, 'nested'), { recursive: true });
    await fs.writeFile(path.join(src, 'a.txt'), 'hello');
    await fs.writeFile(path.join(src, 'nested', 'b.bin'), Buffer.from([1, 2, 3, 4]));

    await fs.mkdir(dst, { recursive: true });

    const calls: string[] = [];
    const key = crypto.randomBytes(32);
    const bundle = await packageState(src, {
      key,
      compression: 'gzip',
      hooks: {
        flush: async () => calls.push('flush'),
        reload: async () => calls.push('reload'),
      },
    });

    expect(calls).toContain('flush');

    await restoreState(bundle, dst, {
      key,
      hooks: {
        flush: async () => calls.push('flush2'),
        reload: async () => calls.push('reload'),
      },
    });

    expect(calls).toContain('reload');
    expect(await fs.readFile(path.join(dst, 'a.txt'), 'utf8')).toBe('hello');
    expect(await fs.readFile(path.join(dst, 'nested', 'b.bin'))).toEqual(Buffer.from([1, 2, 3, 4]));

    // Hash mismatch throws.
    const bad: MigrationBundle = { ...bundle, bundleHash: hex32('ff') };
    await expect(restoreState(bad, dst, { key })).rejects.toBeInstanceOf(BundleHashMismatchError);
  });
});

describe('executor', () => {
  function baseDecision(): MigrationDecision {
    return { migrate: true, reason: 'test', urgency: 'emergency', when: 100n };
  }

  function basePlan(destShellId: Hex): MigrationPlan {
    const discovered: DiscoveredOffer = {
      offer: offerTemplate({ shell_id: destShellId }),
      signature: '0x' as Hex,
      endpoint: 'http://dest',
      operator: 'opB',
    };
    const ranked: RankedDestination = { discovered, score: 123 };
    return {
      decision: baseDecision(),
      primary: ranked,
      fallbacks: [],
      migrateAtEpoch: 100n,
      estimatedBundleBytes: 1n,
    };
  }

  it('executes 3 phases in order (happy path)', async () => {
    const calls: string[] = [];
    const events: any[] = [];
    const histories: any[] = [];

    const ghostId = hex32('99');
    const destShellId = hex32('77');
    const ctx = baseCtx();
    ctx.anomalies = { level: 'emergency', reasons: ['boom'] };

    let session: SessionState = {
      shell_id: ctx.current.shellId,
      staging: false,
      pending_migration: false,
      mig_dest_shell_id: ZERO32,
      mig_dest_session_id: 0n,
      mig_expiry_epoch: 0n,
    };

    const deps: any = {
      ghostId,
      shellRegistry: {} as any,
      sessionManager: {
        startMigration: async (_g: Hex, to: Hex, _h: Hex) => {
          calls.push('startMigration');
          session = {
            ...session,
            pending_migration: true,
            mig_dest_shell_id: to,
            mig_dest_session_id: 1n,
            mig_expiry_epoch: 1000n,
          };
        },
        cancelMigration: async () => calls.push('cancelMigration'),
        finalizeMigration: async () => {
          calls.push('finalizeMigration');
          session = { ...session, shell_id: destShellId, staging: false, pending_migration: false };
        },
        getSession: async () => session,
      },
      offerDiscovery: {
        queryOffers: async () => [],
        rankOffers: async () => [],
      },
      planner: {
        shouldMigrate: () => baseDecision(),
        plan: () => basePlan(destShellId),
      },
      statePackager: {
        estimateBytes: async () => 1n,
        package: async () => {
          calls.push('packageState');
          return { encryptedState: new Uint8Array([1]), bundleHash: hex32('ab'), metadata: anyMeta() };
        },
        restore: async () => {},
      },
      http: {
        postState: async () => {
          calls.push('postState');
          return { bundleHash: hex32('ab'), proof: hex32('cd') };
        },
      },
      hooks: { flush: async () => {}, reload: async () => {} },
      vault: {
        getKey: async () => crypto.randomBytes(32),
      },
      checkpoint: {
        vaultState: async () => calls.push('vaultState'),
        publishCheckpoint: async () => {
          calls.push('publishCheckpoint');
          return hex32('ee');
        },
        distributeRecoveryShares: async () => calls.push('distributeShares'),
      },
      heartbeat: { start: async () => calls.push('heartbeat.start') },
      health: { check: async () => (calls.push('health.check'), true) },
      store: {
        getAttemptCount: async () => 0,
        incrementAttemptCount: async () => (calls.push('incrementAttemptCount'), 1),
        recordEvent: async (_g: Hex, e: any) => events.push(e),
        recordHistory: async (_g: Hex, h: any) => histories.push(h),
      },
      timing: { nowEpoch: async () => 100n, sleepMs: async () => {} },
      limits: { maxMigrationAttempts: 3, pollIntervalMs: 0, stageOpenTimeoutMs: 1, finalizeTimeoutMs: 1 },
    };

    const ex = new MigrationExecutor(deps);
    const res = await ex.execute('/tmp/agent', ctx);
    expect(res.status).toBe('succeeded');

    expect(calls.indexOf('vaultState')).toBeLessThan(calls.indexOf('publishCheckpoint'));
    expect(calls.indexOf('publishCheckpoint')).toBeLessThan(calls.indexOf('distributeShares'));
    expect(calls.indexOf('distributeShares')).toBeLessThan(calls.indexOf('packageState'));
    expect(calls.indexOf('packageState')).toBeLessThan(calls.indexOf('startMigration'));
    expect(calls.indexOf('startMigration')).toBeLessThan(calls.indexOf('postState'));
    expect(calls.indexOf('postState')).toBeLessThan(calls.indexOf('finalizeMigration'));
    expect(calls.indexOf('finalizeMigration')).toBeLessThan(calls.indexOf('heartbeat.start'));
    expect(calls.indexOf('heartbeat.start')).toBeLessThan(calls.indexOf('health.check'));

    expect(histories[0]?.status).toBe('succeeded');
  });

  it('aborts before finalization and cancels migration on transfer failure', async () => {
    const calls: string[] = [];
    const ghostId = hex32('99');
    const destShellId = hex32('77');
    const ctx = baseCtx();
    ctx.anomalies = { level: 'emergency', reasons: ['boom'] };

    let session: SessionState = {
      shell_id: ctx.current.shellId,
      staging: false,
      pending_migration: false,
      mig_dest_shell_id: ZERO32,
      mig_dest_session_id: 0n,
      mig_expiry_epoch: 0n,
    };

    const deps: any = {
      ghostId,
      shellRegistry: {} as any,
      sessionManager: {
        startMigration: async (_g: Hex, to: Hex, _h: Hex) => {
          calls.push('startMigration');
          session = { ...session, pending_migration: true, mig_dest_shell_id: to, mig_dest_session_id: 1n };
        },
        cancelMigration: async () => calls.push('cancelMigration'),
        finalizeMigration: async () => calls.push('finalizeMigration'),
        getSession: async () => session,
      },
      offerDiscovery: { queryOffers: async () => [], rankOffers: async () => [] },
      planner: { shouldMigrate: () => baseDecision(), plan: () => basePlan(destShellId) },
      statePackager: {
        estimateBytes: async () => 1n,
        package: async () => ({ encryptedState: new Uint8Array([1]), bundleHash: hex32('ab'), metadata: anyMeta() }),
        restore: async () => {},
      },
      http: {
        postState: async () => {
          calls.push('postState');
          throw new Error('boom');
        },
      },
      hooks: { flush: async () => {}, reload: async () => {} },
      vault: { getKey: async () => crypto.randomBytes(32) },
      checkpoint: {
        vaultState: async () => {},
        publishCheckpoint: async () => hex32('ee'),
        distributeRecoveryShares: async () => {},
      },
      heartbeat: { start: async () => calls.push('heartbeat.start') },
      health: { check: async () => true },
      store: {
        getAttemptCount: async () => 0,
        incrementAttemptCount: async () => (calls.push('incrementAttemptCount'), 1),
        recordEvent: async () => {},
        recordHistory: async () => {},
      },
      timing: { nowEpoch: async () => 100n, sleepMs: async () => {} },
      limits: { maxMigrationAttempts: 3, pollIntervalMs: 0, stageOpenTimeoutMs: 1, finalizeTimeoutMs: 1 },
    };

    const ex = new MigrationExecutor(deps);
    const res = await ex.execute('/tmp/agent', ctx);
    expect(res.status).toBe('aborted');
    expect(calls).toContain('cancelMigration');
    expect(calls).toContain('incrementAttemptCount');
    expect(calls).not.toContain('finalizeMigration');
    expect(calls).not.toContain('heartbeat.start');
  });

  it('fails (no cancel) if finalization times out after finalizeMigration', async () => {
    const calls: string[] = [];
    const ghostId = hex32('99');
    const destShellId = hex32('77');
    const ctx = baseCtx();
    ctx.anomalies = { level: 'emergency', reasons: ['boom'] };

    let session: SessionState = {
      shell_id: ctx.current.shellId,
      staging: false,
      pending_migration: false,
      mig_dest_shell_id: ZERO32,
      mig_dest_session_id: 0n,
      mig_expiry_epoch: 0n,
    };

    const deps: any = {
      ghostId,
      shellRegistry: {} as any,
      sessionManager: {
        startMigration: async (_g: Hex, to: Hex, _h: Hex) => {
          session = { ...session, pending_migration: true, mig_dest_shell_id: to, mig_dest_session_id: 1n };
        },
        cancelMigration: async () => calls.push('cancelMigration'),
        finalizeMigration: async () => calls.push('finalizeMigration'),
        getSession: async () => session, // never changes to finalized
      },
      offerDiscovery: { queryOffers: async () => [], rankOffers: async () => [] },
      planner: { shouldMigrate: () => baseDecision(), plan: () => basePlan(destShellId) },
      statePackager: {
        estimateBytes: async () => 1n,
        package: async () => ({ encryptedState: new Uint8Array([1]), bundleHash: hex32('ab'), metadata: anyMeta() }),
        restore: async () => {},
      },
      http: { postState: async () => ({ bundleHash: hex32('ab'), proof: hex32('cd') }) },
      hooks: { flush: async () => {}, reload: async () => {} },
      vault: { getKey: async () => crypto.randomBytes(32) },
      checkpoint: {
        vaultState: async () => {},
        publishCheckpoint: async () => hex32('ee'),
        distributeRecoveryShares: async () => {},
      },
      heartbeat: { start: async () => calls.push('heartbeat.start') },
      health: { check: async () => true },
      store: {
        getAttemptCount: async () => 0,
        incrementAttemptCount: async () => (calls.push('incrementAttemptCount'), 1),
        recordEvent: async () => {},
        recordHistory: async () => {},
      },
      timing: { nowEpoch: async () => 100n, sleepMs: async () => {} },
      limits: { maxMigrationAttempts: 3, pollIntervalMs: 0, stageOpenTimeoutMs: 1, finalizeTimeoutMs: 0 },
    };

    const ex = new MigrationExecutor(deps);
    const res = await ex.execute('/tmp/agent', ctx);
    expect(res.status).toBe('failed');
    expect(calls).toContain('finalizeMigration');
    expect(calls).not.toContain('cancelMigration');
  });
});

function anyMeta() {
  return {
    compression: 'gzip' as const,
    format: 'json-files-v1' as const,
    fileCount: 0,
    plaintextBytes: 0,
    compressedBytes: 0,
  };
}
