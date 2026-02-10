import { describe, expect, it, vi } from 'vitest';

import type { Hex } from 'viem';

import type { Policy, PolicyDelta } from '../../sdk/src/types/structs.js';

import { LocalPolicyState } from '../src/config/policy.js';
import { MixedPolicyDeltaRejected, PolicyEngine, TecNotVerified, TimelockNotElapsed } from '../src/wallet/policy-engine.js';
import { SpendTracker } from '../src/wallet/spend-tracker.js';
import { WalletManager } from '../src/wallet/wallet-manager.js';

const ZERO32 = ('0x' + '0'.repeat(64)) as Hex;
const ONE32 = ('0x' + '1'.repeat(64)) as Hex;
const TWO32 = ('0x' + '2'.repeat(64)) as Hex;

function policy(overrides: Partial<Policy> = {}): Policy {
  return {
    home_shell: ONE32,
    allowed_shells: [],
    trusted_shells: [TWO32],
    hot_allowance: 100n,
    escape_gas: 10n,
    escape_stable: 20n,
    guardians: ['0xaaaa'] as Hex[],
    t_guardian: 1n,
    roaming_enabled: false,
    ...overrides,
  };
}

function delta(overrides: Partial<PolicyDelta> = {}): PolicyDelta {
  return {
    new_home_shell: ZERO32,
    add_allowed_shells: [],
    remove_allowed_shells: [],
    add_trusted_shells: [],
    remove_trusted_shells: [],
    hot_allowance_delta: 0n,
    escape_gas_delta: 0n,
    escape_stable_delta: 0n,
    new_guardians: [],
    new_t_guardian: 0n,
    roaming_config: '0x',
    ...overrides,
  };
}

describe('PolicyEngine.classifyDelta', () => {
  it('classifies tightening deltas', () => {
    const engine = new PolicyEngine({
      wallet: {
        proposePolicyChange: async () => ZERO32,
        executePolicyChange: async () => {},
        cancelPolicyChange: async () => {},
      },
      policyState: new LocalPolicyState({ wallet: { getPolicy: async () => policy() }, sqlitePath: ':memory:' }),
      timelockMs: 1000,
      tecVerifier: { verifyTec: async () => true },
    });

    expect(engine.classifyDelta(policy(), delta({ remove_allowed_shells: [ONE32] }))).toBe('tightening');
    expect(engine.classifyDelta(policy(), delta({ hot_allowance_delta: -1n }))).toBe('tightening');
    expect(engine.classifyDelta(policy(), delta({ escape_gas_delta: 1n }))).toBe('tightening');
    expect(engine.classifyDelta(policy({ t_guardian: 1n }), delta({ new_t_guardian: 2n }))).toBe('tightening');

    // Guardians add => tightening.
    expect(engine.classifyDelta(policy({ guardians: ['0xaaaa'] as Hex[] }), delta({ new_guardians: ['0xaaaa', '0xbbbb'] as Hex[] }))).toBe(
      'tightening',
    );
  });

  it('classifies loosening deltas', () => {
    const engine = new PolicyEngine({
      wallet: {
        proposePolicyChange: async () => ZERO32,
        executePolicyChange: async () => {},
        cancelPolicyChange: async () => {},
      },
      policyState: new LocalPolicyState({ wallet: { getPolicy: async () => policy() }, sqlitePath: ':memory:' }),
      timelockMs: 1000,
      tecVerifier: { verifyTec: async () => true },
    });

    expect(engine.classifyDelta(policy(), delta({ add_allowed_shells: [ONE32] }))).toBe('loosening');
    expect(engine.classifyDelta(policy(), delta({ hot_allowance_delta: 1n }))).toBe('loosening');
    expect(engine.classifyDelta(policy(), delta({ escape_stable_delta: -1n }))).toBe('loosening');
    expect(engine.classifyDelta(policy({ t_guardian: 2n }), delta({ new_t_guardian: 1n }))).toBe('loosening');
    expect(engine.classifyDelta(policy(), delta({ new_home_shell: ONE32 }))).toBe('loosening');

    // Guardians remove => loosening.
    expect(engine.classifyDelta(policy({ guardians: ['0xaaaa', '0xbbbb'] as Hex[] }), delta({ new_guardians: ['0xaaaa'] as Hex[] }))).toBe(
      'loosening',
    );
  });

  it('classifies mixed deltas', () => {
    const engine = new PolicyEngine({
      wallet: {
        proposePolicyChange: async () => ZERO32,
        executePolicyChange: async () => {},
        cancelPolicyChange: async () => {},
      },
      policyState: new LocalPolicyState({ wallet: { getPolicy: async () => policy() }, sqlitePath: ':memory:' }),
      timelockMs: 1000,
      tecVerifier: { verifyTec: async () => true },
    });

    expect(engine.classifyDelta(policy(), delta({ add_allowed_shells: [ONE32], remove_allowed_shells: [TWO32] }))).toBe('mixed');
  });
});

describe('PolicyEngine behavior', () => {
  it('tightening is immediate (propose + execute)', async () => {
    const ghostId = ONE32;
    const proposalId = TWO32;

    const wallet = {
      getPolicy: vi.fn().mockResolvedValue(policy()),
      proposePolicyChange: vi.fn().mockResolvedValue(proposalId),
      executePolicyChange: vi.fn().mockResolvedValue(undefined),
      cancelPolicyChange: vi.fn().mockResolvedValue(undefined),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });
    const engine = new PolicyEngine({
      wallet,
      policyState,
      timelockMs: 1000,
      tecVerifier: { verifyTec: vi.fn().mockResolvedValue(true) },
    });

    await engine.applyTightening(ghostId, delta({ remove_allowed_shells: [TWO32] }));

    expect(wallet.proposePolicyChange).toHaveBeenCalledTimes(1);
    expect(wallet.executePolicyChange).toHaveBeenCalledTimes(1);
    expect(wallet.executePolicyChange).toHaveBeenCalledWith(ghostId, proposalId);
  });

  it('loosening requires timelock and TEC', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2020-01-01T00:00:00Z'));

    const ghostId = ONE32;
    const proposalId = TWO32;
    const timelockMs = 10_000;

    const wallet = {
      getPolicy: vi.fn().mockResolvedValue(policy()),
      proposePolicyChange: vi.fn().mockResolvedValue(proposalId),
      executePolicyChange: vi.fn().mockResolvedValue(undefined),
      cancelPolicyChange: vi.fn().mockResolvedValue(undefined),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });
    const tecVerifier = { verifyTec: vi.fn().mockResolvedValue(true) };
    const engine = new PolicyEngine({ wallet, policyState, timelockMs, tecVerifier });

    const createdAtMs = Date.now();
    await engine.proposeLoosening(ghostId, delta({ add_allowed_shells: [TWO32] }));

    const p = policyState.getProposal(proposalId);
    expect(p).not.toBeNull();
    expect(p?.executable_at_ms).toBe(createdAtMs + timelockMs);

    await expect(engine.executePending(ghostId, proposalId)).rejects.toBeInstanceOf(TimelockNotElapsed);
    expect(wallet.executePolicyChange).not.toHaveBeenCalled();

    vi.advanceTimersByTime(timelockMs);

    await engine.executePending(ghostId, proposalId);
    expect(tecVerifier.verifyTec).toHaveBeenCalledTimes(1);
    expect(wallet.executePolicyChange).toHaveBeenCalledWith(ghostId, proposalId);

    const p2 = policyState.getProposal(proposalId);
    expect(p2?.status).toBe('executed');

    vi.useRealTimers();
  });

  it('executePending rejects if TEC fails', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2020-01-01T00:00:00Z'));

    const ghostId = ONE32;
    const proposalId = TWO32;
    const timelockMs = 1_000;

    const wallet = {
      getPolicy: vi.fn().mockResolvedValue(policy()),
      proposePolicyChange: vi.fn().mockResolvedValue(proposalId),
      executePolicyChange: vi.fn().mockResolvedValue(undefined),
      cancelPolicyChange: vi.fn().mockResolvedValue(undefined),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });
    const tecVerifier = { verifyTec: vi.fn().mockResolvedValue(false) };
    const engine = new PolicyEngine({ wallet, policyState, timelockMs, tecVerifier });

    await engine.proposeLoosening(ghostId, delta({ add_allowed_shells: [TWO32] }));
    vi.advanceTimersByTime(timelockMs);

    await expect(engine.executePending(ghostId, proposalId)).rejects.toBeInstanceOf(TecNotVerified);
    expect(wallet.executePolicyChange).not.toHaveBeenCalled();

    vi.useRealTimers();
  });
});

describe('Mixed delta rejection', () => {
  it('rejects mixed deltas', async () => {
    const ghostId = ONE32;

    const wallet = {
      getPolicy: vi.fn().mockResolvedValue(policy()),
      getBalance: vi.fn().mockResolvedValue(0n),
      spend: vi.fn().mockResolvedValue(undefined),
      proposePolicyChange: vi.fn().mockResolvedValue(TWO32),
      executePolicyChange: vi.fn().mockResolvedValue(undefined),
      cancelPolicyChange: vi.fn().mockResolvedValue(undefined),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });
    const engine = new PolicyEngine({
      wallet,
      policyState,
      timelockMs: 1000,
      tecVerifier: { verifyTec: vi.fn().mockResolvedValue(true) },
    });

    const wm = new WalletManager({
      wallet,
      policyState,
      policyEngine: engine,
      spendTracker: new SpendTracker(),
    });

    await expect(wm.requestPolicyChange(ghostId, delta({ add_allowed_shells: [ONE32], remove_allowed_shells: [TWO32] }))).rejects.toBeInstanceOf(
      MixedPolicyDeltaRejected,
    );

    expect(wallet.proposePolicyChange).not.toHaveBeenCalled();
  });
});

describe('Policy refresh on chain events', () => {
  it('refreshes cached policy on policy change event', async () => {
    const ghostId = ONE32;
    const p1 = policy({ hot_allowance: 1n });
    const p2 = policy({ hot_allowance: 2n });

    const wallet = {
      getPolicy: vi.fn().mockResolvedValueOnce(p1).mockResolvedValueOnce(p2),
    };

    const policyState = new LocalPolicyState({ wallet, sqlitePath: ':memory:' });

    expect(await policyState.getCurrentPolicy(ghostId)).toEqual(p1);
    expect(await policyState.getCurrentPolicy(ghostId)).toEqual(p1);
    expect(wallet.getPolicy).toHaveBeenCalledTimes(1);

    await policyState.handlePolicyChangedEvent(ghostId);
    expect(wallet.getPolicy).toHaveBeenCalledTimes(2);

    expect(await policyState.getCurrentPolicy(ghostId)).toEqual(p2);
  });
});

