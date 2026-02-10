import { describe, expect, it, vi } from 'vitest';

import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomBytes } from 'node:crypto';

import { GhostDB } from '../src/storage/db.js';
import { GhostDaemon } from '../src/daemon.js';

function buf32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe('SQLite storage', () => {
  it('creates schema, enables WAL, and supports CRUD helpers', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-db-'));
    const db = await GhostDB.open(dir);

    expect(db.getJournalMode().toLowerCase()).toContain('wal');

    db.setMeta('ghost_id', '0x' + '11'.repeat(32));
    expect(db.getMeta('ghost_id')).toBe('0x' + '11'.repeat(32));

    db.insertSession({
      session_id: 1,
      ghost_id: buf32(1),
      shell_id: buf32(2),
      status: 'open',
      start_epoch: 10,
      session_key_public: randomBytes(33),
      params_json: JSON.stringify({ foo: 'bar' }),
    });

    const s = db.getSession(1);
    expect(s?.session_id).toBe(1);
    expect(s?.status).toBe('open');

    db.insertInterval({
      session_id: 1,
      epoch: 10,
      interval_index: 0,
      vi: 1,
      sig_ghost: randomBytes(65),
      sig_shell: randomBytes(65),
      timestamp: Date.now(),
    });

    const ivs = db.getIntervals(1, 10);
    expect(ivs.length).toBe(1);
    expect(ivs[0].vi).toBe(1);

    db.insertCheckpoint({
      ghost_id: buf32(1),
      epoch: 10,
      checkpoint_commitment: randomBytes(32),
      envelope_commitment: randomBytes(32),
      ptr_checkpoint: 'ipfs://checkpoint',
      ptr_envelope: 'ipfs://envelope',
      created_at: Date.now(),
    });

    const latest = db.getLatestCheckpoint(buf32(1));
    expect(latest?.epoch).toBe(10);

    db.insertShareDistribution({
      ghost_id: buf32(1),
      epoch: 10,
      shell_id: buf32(2),
      share_index: 0,
      receipt_sig_shell: randomBytes(65),
      receipt_sig_ack: randomBytes(65),
      distributed_at: Date.now(),
    });

    const shares = db.getShareDistributions(buf32(1), 10);
    expect(shares.length).toBe(1);

    db.upsertShellReputation({
      shell_id: buf32(2),
      total_sessions: 5,
      missed_heartbeat_rate: 0.01,
      receipt_mismatches: 0,
      last_session_epoch: 10,
      notes: 'ok',
    });

    const rep = db.getShellReputation(buf32(2));
    expect(rep?.total_sessions).toBe(5);

    db.insertPolicyProposal({
      proposal_id: buf32(9),
      ghost_id: buf32(1),
      delta_json: JSON.stringify({ a: 1 }),
      classification: 'low',
      proposed_at: 100,
      executable_at: 200,
    });

    const pending0 = db.getPendingPolicyProposals(150);
    expect(pending0.length).toBe(0);
    const pending1 = db.getPendingPolicyProposals(200);
    expect(pending1.length).toBe(1);

    db.markPolicyExecuted(buf32(9));
    expect(db.getPendingPolicyProposals(999).length).toBe(0);

    db.setChainCursor(123);
    expect(db.getChainCursor()).toBe(123);

    db.close();
  });
});

describe('Daemon lifecycle', () => {
  it('runs startup/shutdown sequence and calls module hooks', async () => {
    const calls: string[] = [];

    const config = {
      ghostId: ('0x' + '11'.repeat(32)) as any,
      identityKeyPath: '/tmp/identity.key',
      walletAddress: '0x1111111111111111111111111111111111111111',
      rpcUrl: 'https://example.invalid',
      chainId: 1n,
      deployment: {
        chain_id: 1n,
        git_token: '0x0000000000000000000000000000000000000001',
        shell_registry: '0x0000000000000000000000000000000000000002',
        ghost_registry: '0x0000000000000000000000000000000000000003',
        session_manager: '0x0000000000000000000000000000000000000004',
        receipt_manager: '0x0000000000000000000000000000000000000005',
        rewards_manager: '0x0000000000000000000000000000000000000006',
        verifier_registry: '0x0000000000000000000000000000000000000007',
      },
      maxPricePerSU: 0n,
      preferredAssuranceTier: 0,
      minAssuranceTier: 0,
      preferredLeaseEpochs: 1n,
      autoRenewLease: false,
      migration: {
        enabled: false,
        triggers: { missedHeartbeats: false, verifierSlash: false, measurementRevoked: false },
        preferences: { preferTrustedShells: true },
        timing: { maxDelayEpochs: 0n, cooldownEpochs: 0n },
      },
      vaulting: {
        enabled: false,
        checkpointIntervalEpochs: 1n,
        shamir: { t: 2, n: 3 },
        encryption: { kdf: 'scrypt', saltBytes: 16 },
      },
      recovery: {
        recoverySetShellIds: [],
        threshold: 0,
        bounty: { asset: '0x0000000000000000000000000000000000000000', total: 0n, bpsInitiator: 0n },
      },
      agentRuntime: 'generic',
      agentDataDir: '/tmp/agent',
      agentSocketPath: '/tmp/agent.sock',
      dataDir: '/tmp',
      telemetry: { logLevel: 'error' },
    };

    const identity = {
      privKey: new Uint8Array(32).fill(1),
      privKeyHex: ('0x' + '01'.repeat(32)) as any,
      account: { address: '0x1111111111111111111111111111111111111111', sign: async () => '0x' as any } as any,
      identityPubkeyBytes: '0xdeadbeef' as any,
    };

    const db = {
      getChainCursor: () => 0,
      setChainCursor: vi.fn(),
      listSessions: () => [],
      close: vi.fn(),
    } as any;

    const chainListener = {
      start: vi.fn(async () => calls.push('chainListener.start')),
      stop: vi.fn(async () => calls.push('chainListener.stop')),
    } as any;

    const publicClient = {
      readContract: vi.fn(async ({ functionName }: any) => {
        if (functionName === 'getGhost') {
          return {
            wallet: config.walletAddress,
            identity_pubkey: identity.identityPubkeyBytes,
            bond_asset: '0x0000000000000000000000000000000000000000',
            bond_amount: 0n,
          };
        }
        if (functionName === 'GENESIS_TIME') return 1000n;
        if (functionName === 'EPOCH_LEN') return 10n;
        if (functionName === 'getSession') return { mode: 0n };
        throw new Error('unexpected readContract');
      }),
    } as any;

    const daemon = new GhostDaemon({
      configPath: '/ignored',
      deps: {
        loadConfig: async () => config as any,
        loadIdentityKey: async () => identity as any,
        openDb: async () => db,
        createPublicClient: () => publicClient,
        createWatchClient: () => undefined,
        createChainListener: () => chainListener,
        createEpochClock: (g, e) => ({
          currentEpoch: () => 0n,
          secondsRemaining: () => 1n,
          genesis_time: g,
          epoch_length: e,
          epochAt: () => 0n,
          epochStart: () => 0n,
          epochEnd: () => 0n,
        }) as any,
      },
    });

    daemon.registerModule('modA', {
      onStart: async () => calls.push('modA.start'),
      onStop: async () => calls.push('modA.stop'),
    });

    daemon.registerModule('modB', {
      onStart: async () => calls.push('modB.start'),
      onStop: async () => calls.push('modB.stop'),
    });

    await daemon.start({ identityPassphrase: 'x' });
    await daemon.stop();

    expect(calls).toEqual([
      'chainListener.start',
      'modA.start',
      'modB.start',
      'modB.stop',
      'modA.stop',
      'chainListener.stop',
    ]);

    expect(db.close).toHaveBeenCalledTimes(1);
  });
});
