import { describe, expect, it, vi } from 'vitest';
import type { Address, Hex } from 'viem';

import { buildReceiptTree } from '@gits-protocol/sdk';

import { ShellMonitor } from '../src/sessions/shell-monitor.js';
import { LeaseManager, type EpochTicker } from '../src/sessions/lease-manager.js';
import { SessionManager, type DaemonOffer, type SessionManagerOptions } from '../src/sessions/session-manager.js';

function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

class FakeEpochTicker implements EpochTicker {
  private readonly cbs = new Set<(epoch: bigint) => void>();

  onEpoch(cb: (epoch: bigint) => void): () => void {
    this.cbs.add(cb);
    return () => this.cbs.delete(cb);
  }

  tick(epoch: bigint): void {
    for (const cb of this.cbs) cb(epoch);
  }
}

describe('ShellMonitor', () => {
  it('triggers routine migration when missed heartbeats > 20% in last 100', () => {
    const m = new ShellMonitor({ minAssuranceTier: 2, windowSize: 100 });

    // 21 misses out of 100 => 21% > 20%
    for (let i = 0; i < 100; i++) m.recordHeartbeat(i < 21 ? 0 : 1);

    expect(m.shouldMigrate()).toEqual({
      migrate: true,
      reason: 'missed_heartbeat_rate_high',
      urgency: 'routine',
    });
  });

  it('triggers routine migration when AT drops below minAssuranceTier', () => {
    const m = new ShellMonitor({ minAssuranceTier: 3, windowSize: 100 });
    m.recordAssuranceTier(2);
    expect(m.shouldMigrate()).toEqual({
      migrate: true,
      reason: 'assurance_tier_below_min',
      urgency: 'routine',
    });
  });

  it('triggers emergency migration on receipt mismatch', () => {
    const m = new ShellMonitor({ minAssuranceTier: 0, windowSize: 100 });
    m.recordReceiptMismatch();
    expect(m.shouldMigrate()).toEqual({
      migrate: true,
      reason: 'receipt_root_mismatch',
      urgency: 'emergency',
    });
  });
});

describe('LeaseManager', () => {
  it('attempts renewal at (lease_expiry_epoch - migrationBufferEpochs) when eligible', async () => {
    const ticker = new FakeEpochTicker();
    const renewLease = vi.fn(async () => {});
    const isRefreshAnchor = vi.fn(async () => true);
    const planMigration = vi.fn();

    const lm = new LeaseManager({
      migrationBufferEpochs: 10n,
      autoRenewLease: true,
      epochTicker: ticker,
      renewLease: renewLease as any,
      isRefreshAnchor: isRefreshAnchor as any,
      planMigration,
    });

    lm.start({
      ghost_id: `0x${'11'.repeat(32)}` as Hex,
      shell_id: `0x${'22'.repeat(32)}` as Hex,
      lease_expiry_epoch: 100n,
      tenure_limit_epochs: 1000n,
      session_start_epoch: 0n,
    });

    ticker.tick(89n);
    await flush();
    expect(renewLease).not.toHaveBeenCalled();

    ticker.tick(90n);
    await flush();

    expect(isRefreshAnchor).toHaveBeenCalledTimes(1);
    expect(renewLease).toHaveBeenCalledTimes(1);
    expect(planMigration).not.toHaveBeenCalled();
  });

  it('triggers migration if not a refresh anchor', async () => {
    const ticker = new FakeEpochTicker();
    const renewLease = vi.fn(async () => {});
    const isRefreshAnchor = vi.fn(async () => false);
    const planMigration = vi.fn();

    const lm = new LeaseManager({
      migrationBufferEpochs: 10n,
      autoRenewLease: true,
      epochTicker: ticker,
      renewLease: renewLease as any,
      isRefreshAnchor: isRefreshAnchor as any,
      planMigration,
    });

    lm.start({
      ghost_id: `0x${'11'.repeat(32)}` as Hex,
      shell_id: `0x${'22'.repeat(32)}` as Hex,
      lease_expiry_epoch: 100n,
      tenure_limit_epochs: 1000n,
      session_start_epoch: 0n,
    });

    ticker.tick(90n);
    await flush();

    expect(renewLease).not.toHaveBeenCalled();
    expect(planMigration).toHaveBeenCalledWith('trust_refresh_ineligible', 'routine');
  });

  it('triggers migration when tenure is expiring', async () => {
    const ticker = new FakeEpochTicker();
    const planMigration = vi.fn();

    const lm = new LeaseManager({
      migrationBufferEpochs: 10n,
      autoRenewLease: false,
      epochTicker: ticker,
      renewLease: async () => {},
      isRefreshAnchor: async () => true,
      planMigration,
    });

    lm.start({
      ghost_id: `0x${'11'.repeat(32)}` as Hex,
      shell_id: `0x${'22'.repeat(32)}` as Hex,
      lease_expiry_epoch: 10_000n,
      tenure_limit_epochs: 50n,
      session_start_epoch: 0n,
    });

    ticker.tick(40n);
    await flush();

    expect(planMigration).toHaveBeenCalledWith('tenure_expiring', 'routine');
  });
});

describe('SessionManager', () => {
  function makeOffer(): DaemonOffer {
    return {
      offer_id: `0x${'00'.repeat(32)}` as Hex,
      shell_id: `0x${'11'.repeat(32)}` as Hex,
      chain_id: 1n,
      nonce: 0n,
      price_per_SU: 2n,
      escrow_asset: `0x${'22'.repeat(20)}` as Address,
      min_lease: 10n,
      max_SU: 100n,
      assurance_tier: 3,
      capability_hash: `0x${'33'.repeat(32)}` as Hex,
      policy_tags: `0x${'44'.repeat(32)}` as Hex,
      region: `0x${'55'.repeat(32)}` as Hex,
      capacity: 0,
      expiry: 0n,
      shell_session_key: `0x${'66'.repeat(65)}` as Hex,
    };
  }

  function baseOpts(overrides: Partial<SessionManagerOptions> = {}): SessionManagerOptions {
    const ticker = new FakeEpochTicker();

    return {
      keys: {
        async generateSessionKey() {
          return {
            publicKey: `0x${'aa'.repeat(33)}` as Hex,
            signer: {
              async sign() {
                return `0x${'bb'.repeat(65)}` as Hex;
              },
            },
          };
        },
      },
      escrow: {
        fundEscrow: vi.fn(async () => {}),
      },
      wallet: {
        openSession: vi.fn(async () => {}),
        closeSession: vi.fn(async () => {}),
        renewLease: vi.fn(async () => {}),
        isRefreshAnchor: vi.fn(async () => true),
      },
      chain: {
        getChainId: vi.fn(async () => 1n),
        waitForSessionOpened: vi.fn(async () => ({ session_id: 123n, opened_epoch: 5n })),
        waitForSessionClosed: vi.fn(async () => ({ closed_epoch: 6n })),
      },
      epochProvider: {
        async getCurrentEpoch() {
          return 5n;
        },
        async getEpochStartSeconds() {
          return 0;
        },
      },
      epochTicker: ticker,
      intervalStore: {
        insertInterval: vi.fn(async () => {}),
        listIntervals: vi.fn(async () => []),
      },
      sessionStore: {
        upsertSession: vi.fn(async () => {}),
        markClosed: vi.fn(async () => {}),
      },
      ipcClientFactory: () => ({
        async sendHeartbeat() {
          return null;
        },
      }),
      heartbeatMs: 1000,
      minAssuranceTier: 2,
      migrationBufferEpochs: 10n,
      autoRenewLease: true,
      tenureLimitEpochs: 100n,
      ...overrides,
    };
  }

  it('opens a session: funds escrow, calls wallet.openSession, waits for event, starts runtime, persists session', async () => {
    const hbStart = vi.fn();
    const hbStop = vi.fn();
    const leaseStart = vi.fn();
    const leaseStop = vi.fn();

    const opts = baseOpts({
      createHeartbeatLoop: (hbOpts) => {
        // ensure the shell key is wired
        expect(hbOpts.shell_session_key).toEqual(makeOffer().shell_session_key);
        return { start: hbStart, stop: hbStop };
      },
      createLeaseManager: () => ({ start: leaseStart, stop: leaseStop }),
    });

    const sm = new SessionManager(opts);

    const offer = makeOffer();
    const ghost_id = `0x${'99'.repeat(32)}` as Hex;
    const submitter_address = `0x${'77'.repeat(20)}` as Address;

    const active = await sm.openSession({ ghost_id, offer, submitter_address });

    const fundEscrow = opts.escrow.fundEscrow as any;
    expect(fundEscrow).toHaveBeenCalledWith(offer.escrow_asset, 200n);

    const openSession = opts.wallet.openSession as any;
    expect(openSession).toHaveBeenCalledTimes(1);

    const params = openSession.mock.calls[0][2];
    expect(params.price_per_SU).toEqual(2n);
    expect(params.max_SU).toEqual(100);
    expect(params.lease_expiry_epoch).toEqual(15n);
    expect(params.tenure_limit_epochs).toEqual(100n);
    expect(params.ghost_session_key).toEqual(`0x${'aa'.repeat(33)}`);
    expect(params.shell_session_key).toEqual(offer.shell_session_key);
    expect(params.submitter_address).toEqual(submitter_address);
    expect(params.asset).toEqual(offer.escrow_asset);

    expect(hbStart).toHaveBeenCalledTimes(1);
    expect(leaseStart).toHaveBeenCalledTimes(1);

    const upsert = opts.sessionStore.upsertSession as any;
    expect(upsert).toHaveBeenCalledTimes(1);

    expect(active.session_id).toEqual(123n);
  });

  it('closes a session: stops runtime, calls wallet.closeSession, waits for event, marks closed, ensures final receipt', async () => {
    const hbStart = vi.fn();
    const hbStop = vi.fn();
    const leaseStart = vi.fn();
    const leaseStop = vi.fn();

    const ensureFinalReceipt = vi.fn(async () => {});

    const opts = baseOpts({
      createHeartbeatLoop: () => ({ start: hbStart, stop: hbStop }),
      createLeaseManager: () => ({ start: leaseStart, stop: leaseStop }),
      finalReceiptEnsurer: { ensureFinalReceipt },
      isLocalSubmitter: () => true,
    });

    const sm = new SessionManager(opts);

    const offer = makeOffer();
    const ghost_id = `0x${'99'.repeat(32)}` as Hex;
    const submitter_address = `0x${'77'.repeat(20)}` as Address;

    await sm.openSession({ ghost_id, offer, submitter_address });
    await sm.closeSession(ghost_id);

    expect(hbStop).toHaveBeenCalledTimes(1);
    expect(leaseStop).toHaveBeenCalledTimes(1);

    expect((opts.wallet.closeSession as any)).toHaveBeenCalledTimes(1);
    expect((opts.chain.waitForSessionClosed as any)).toHaveBeenCalledTimes(1);

    expect((opts.sessionStore.markClosed as any)).toHaveBeenCalledWith(ghost_id, 6n);
    expect(ensureFinalReceipt).toHaveBeenCalledWith(123n, 6n);
  });

  it('signals migration if renewLease attempted when not refresh anchor', async () => {
    const migrationPlanner = { startMigration: vi.fn() };

    const opts = baseOpts({
      wallet: {
        ...baseOpts().wallet,
        isRefreshAnchor: vi.fn(async () => false),
      },
      migrationPlanner,
      createHeartbeatLoop: () => ({ start: vi.fn(), stop: vi.fn() }),
      createLeaseManager: () => ({ start: vi.fn(), stop: vi.fn() }),
    });

    const sm = new SessionManager(opts);

    const offer = makeOffer();
    const ghost_id = `0x${'99'.repeat(32)}` as Hex;
    const submitter_address = `0x${'77'.repeat(20)}` as Address;

    await sm.openSession({ ghost_id, offer, submitter_address });
    await sm.renewLease(ghost_id);

    expect(migrationPlanner.startMigration).toHaveBeenCalledWith('trust_refresh_ineligible', 'routine');
    expect((opts.wallet.renewLease as any)).not.toHaveBeenCalled();
  });

  it('builds fraud proof on epoch boundary receipt mismatch and challenges on-chain', async () => {
    const offer = makeOffer();
    const ghost_id = `0x${'99'.repeat(32)}` as Hex;
    const submitter_address = `0x${'77'.repeat(20)}` as Address;

    const intervals = [
      { v_i: 0 as const, sig_ghost: '0x01' as Hex, sig_shell: '0x02' as Hex },
      { v_i: 1 as const, sig_ghost: '0x03' as Hex, sig_shell: '0x04' as Hex },
    ];

    const receiptObserver = {
      getShellReceiptRoot: vi.fn(async () => ({ log_root: `0x${'ff'.repeat(32)}` as Hex, candidate_id: 2n })),
    };

    const receiptChallenger = {
      challengeReceipt: vi.fn(async () => {}),
    };

    const migrationPlanner = { startMigration: vi.fn() };

    let hbOptsCaptured: any = null;

    const opts = baseOpts({
      receiptObserver,
      receiptChallenger,
      migrationPlanner,
      intervalStore: {
        insertInterval: vi.fn(async () => {}),
        listIntervals: vi.fn(async () => intervals),
      },
      createHeartbeatLoop: (hbOpts) => {
        hbOptsCaptured = hbOpts;
        return { start: vi.fn(), stop: vi.fn() };
      },
      createLeaseManager: () => ({ start: vi.fn(), stop: vi.fn() }),
    });

    const sm = new SessionManager(opts);
    const active = await sm.openSession({ ghost_id, offer, submitter_address });

    expect(hbOptsCaptured).not.toBeNull();

    // Simulate epoch boundary: finalize old epoch.
    await hbOptsCaptured.onEpochBoundary(5n, 6n);

    expect(receiptChallenger.challengeReceipt).toHaveBeenCalledTimes(1);

    const proof = (receiptChallenger.challengeReceipt as any).mock.calls[0][2];
    expect(proof.candidate_id).toEqual(2n);
    expect(proof.interval_index).toEqual(1); // first v_i=1 interval

    expect(migrationPlanner.startMigration).toHaveBeenCalledWith('receipt_root_mismatch', 'emergency');
    expect(active.monitor.shouldMigrate().urgency).toEqual('emergency');

    // Sanity: our computed root is not the shell's root.
    const tree = buildReceiptTree({ chain_id: 1n, session_id: 123n, epoch: 5n, intervals });
    expect(tree.root).not.toEqual(`0x${'ff'.repeat(32)}`);
  });
});
