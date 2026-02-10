import { describe, expect, it, vi } from 'vitest';

import type { Hex } from 'viem';

import type { Policy, SessionParams } from '../../sdk/src/types/structs.js';

import { LocalPolicyState } from '../src/config/policy.js';
import { GhostDB } from '../src/storage/db.js';
import { EscrowManager, requiredEscrow } from '../src/wallet/escrow.js';
import { EscapeReservesViolation, SpendTracker } from '../src/wallet/spend-tracker.js';

const ZERO32 = ('0x' + '0'.repeat(64)) as Hex;

function policy(overrides: Partial<Policy> = {}): Policy {
  return {
    home_shell: ZERO32,
    allowed_shells: [],
    trusted_shells: [],
    hot_allowance: 0n,
    escape_gas: 0n,
    escape_stable: 0n,
    guardians: [],
    t_guardian: 0n,
    roaming_enabled: false,
    ...overrides,
  };
}

describe('SpendTracker', () => {
  it('SpendTracker with persistence survives restart', () => {
    const db = new GhostDB(':memory:');
    try {
      const ghostIdBytes = Buffer.from(ZERO32.slice(2), 'hex');

      const st1 = new SpendTracker(db, ghostIdBytes);
      st1.loadEpoch(5n);
      st1.recordSpend(123n);

      const st2 = new SpendTracker(db, ghostIdBytes);
      st2.loadEpoch(5n);
      expect(st2.spentThisEpoch).toBe(123n);
    } finally {
      db.close();
    }
  });

  it('SpendTracker without store works in-memory', () => {
    const st = new SpendTracker();
    st.recordSpend(5n);
    expect(st.spentThisEpoch).toBe(5n);
  });

  it('SpendTracker.loadEpoch auto-resets on new epoch', () => {
    const st = new SpendTracker();
    st.loadEpoch(5n);
    st.recordSpend(10n);
    expect(st.spentThisEpoch).toBe(10n);

    st.loadEpoch(6n);
    expect(st.spentThisEpoch).toBe(0n);
  });

  it('canSpend at limit', () => {
    const st = new SpendTracker();
    const p = policy({ hot_allowance: 100n });

    expect(st.canSpend(100n, p)).toBe(true);
    st.recordSpend(100n);
    expect(st.canSpend(1n, p)).toBe(false);
  });

  it('canSpend over limit', () => {
    const st = new SpendTracker();
    const p = policy({ hot_allowance: 100n });

    st.recordSpend(60n);
    expect(st.canSpend(41n, p)).toBe(false);
  });

  it('after resetEpoch', () => {
    const st = new SpendTracker();
    const p = policy({ hot_allowance: 50n });

    st.recordSpend(50n);
    expect(st.canSpend(1n, p)).toBe(false);
    st.resetEpoch();
    expect(st.canSpend(50n, p)).toBe(true);
  });

  it('escape reserve protection', () => {
    const st = new SpendTracker();
    const p = policy({ escape_gas: 10n, escape_stable: 20n });

    st.recordSpend(30n);
    expect(st.verifyEscapeReserves(p, 60n)).toBe(true); // 10 + 20 + 30
    expect(st.verifyEscapeReserves(p, 59n)).toBe(false);
  });
});

describe('Escrow', () => {
  it('requiredEscrow(sessionParams) = price_per_SU * max_SU', () => {
    const params: SessionParams = {
      price_per_SU: 5n,
      max_SU: 10,
      lease_expiry_epoch: 0n,
      tenure_limit_epochs: 0n,
      ghost_session_key: '0x',
      shell_session_key: '0x',
      submitter_address: '0x0000000000000000000000000000000000000000',
      asset: '0x0000000000000000000000000000000000000000',
    };

    expect(requiredEscrow(params)).toBe(50n);
  });

  it('refuses to fund if escape reserves would be violated', async () => {
    const ghostId = ZERO32;
    const sessionId = 1n;

    const wallet = {
      getPolicy: vi.fn().mockResolvedValue(policy({ hot_allowance: 1_000_000n, escape_gas: 10n, escape_stable: 20n })),
      getBalance: vi.fn().mockResolvedValue(79n),
      fundNextEpoch: vi.fn().mockResolvedValue(undefined),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });
    const spendTracker = new SpendTracker();

    const sessions = {
      getSessionParams: vi.fn().mockResolvedValue({
        price_per_SU: 5n,
        max_SU: 10,
        lease_expiry_epoch: 0n,
        tenure_limit_epochs: 0n,
        ghost_session_key: '0x',
        shell_session_key: '0x',
        submitter_address: '0x0000000000000000000000000000000000000000',
        asset: '0x0000000000000000000000000000000000000000',
      } satisfies SessionParams),
    };

    const escrow = new EscrowManager({ wallet, policyState, spendTracker, sessions });

    await expect(escrow.fundNextEpoch(ghostId, sessionId)).rejects.toBeInstanceOf(EscapeReservesViolation);
    expect(wallet.fundNextEpoch).not.toHaveBeenCalled();
  });
});
