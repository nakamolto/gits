import type { Address, Hex } from 'viem';

import type { Policy, PolicyDelta } from '../../../sdk/src/types/structs.js';
import { LocalPolicyState } from '../config/policy.js';
import { MixedPolicyDeltaRejected, PolicyEngine } from './policy-engine.js';
import { EscapeReservesViolation, SpendTracker } from './spend-tracker.js';

export class HotAllowanceExceeded extends Error {
  constructor() {
    super('Hot allowance exceeded');
  }
}

export class InsufficientBalance extends Error {
  constructor() {
    super('Insufficient wallet balance');
  }
}

export interface GhostWalletClient {
  getBalance(ghostId: Hex): Promise<bigint>;
  spend(ghostId: Hex, to: Address, amount: bigint): Promise<void>;
  getPolicy(ghostId: Hex): Promise<Policy>;
}

export class WalletManager {
  private readonly wallet: GhostWalletClient;
  private readonly policyState: LocalPolicyState;
  private readonly policyEngine: PolicyEngine;
  private readonly spendTracker: SpendTracker;
  private readonly epochProvider?: () => bigint;

  constructor(opts: {
    wallet: GhostWalletClient;
    policyState: LocalPolicyState;
    policyEngine: PolicyEngine;
    spendTracker: SpendTracker;
    epochProvider?: () => bigint;
  }) {
    this.wallet = opts.wallet;
    this.policyState = opts.policyState;
    this.policyEngine = opts.policyEngine;
    this.spendTracker = opts.spendTracker;
    this.epochProvider = opts.epochProvider;
  }

  async getBalance(ghostId: Hex): Promise<bigint> {
    return this.wallet.getBalance(ghostId);
  }

  async getCurrentPolicy(ghostId: Hex): Promise<Policy> {
    return this.policyState.getCurrentPolicy(ghostId);
  }

  async spend(ghostId: Hex, to: Address, amount: bigint): Promise<void> {
    const epoch = this.epochProvider?.();
    const stAny = this.spendTracker as any;
    if (epoch !== undefined && typeof stAny.loadEpoch === 'function') stAny.loadEpoch(epoch);

    const policy = await this.getCurrentPolicy(ghostId);

    if (!this.spendTracker.canSpend(amount, policy)) {
      throw new HotAllowanceExceeded();
    }

    const balance = await this.getBalance(ghostId);
    if (amount > balance) throw new InsufficientBalance();

    const postSpendBalance = balance - amount;
    if (!this.spendTracker.verifyEscapeReserves(policy, postSpendBalance)) {
      throw new EscapeReservesViolation();
    }

    await this.wallet.spend(ghostId, to, amount);
    this.spendTracker.recordSpend(amount);
  }

  async requestPolicyChange(ghostId: Hex, delta: PolicyDelta): Promise<Hex> {
    const current = await this.getCurrentPolicy(ghostId);
    const kind = this.policyEngine.classifyDelta(current, delta);

    if (kind === 'mixed') throw new MixedPolicyDeltaRejected();
    if (kind === 'tightening') return this.policyEngine.applyTightening(ghostId, delta);

    return this.policyEngine.proposeLoosening(ghostId, delta);
  }
}
