import type { Hex } from 'viem';

import type { SessionParams } from '../../../sdk/src/types/structs.js';
import { LocalPolicyState } from '../config/policy.js';
import { EscapeReservesViolation, SpendTracker } from './spend-tracker.js';
import { HotAllowanceExceeded, InsufficientBalance } from './wallet-manager.js';

export interface GhostWalletEscrowClient {
  getBalance(ghostId: Hex): Promise<bigint>;
  fundNextEpoch(ghostId: Hex, amount: bigint): Promise<void>;
}

export interface SessionParamsProvider {
  getSessionParams(sessionId: bigint): Promise<SessionParams>;
}

export interface SessionFundingStateProvider {
  autoRenewLease(ghostId: Hex): Promise<boolean>;
  isNextEpochFunded(ghostId: Hex): Promise<boolean>;
  getActiveSessionId(ghostId: Hex): Promise<bigint | null>;
}

export function requiredEscrow(sessionParams: SessionParams): bigint {
  return sessionParams.price_per_SU * BigInt(sessionParams.max_SU);
}

export class EscrowManager {
  private readonly wallet: GhostWalletEscrowClient;
  private readonly policyState: LocalPolicyState;
  private readonly spendTracker: SpendTracker;
  private readonly sessions: SessionParamsProvider;
  private readonly fundingState?: SessionFundingStateProvider;
  private readonly epochProvider?: () => bigint;

  constructor(opts: {
    wallet: GhostWalletEscrowClient;
    policyState: LocalPolicyState;
    spendTracker: SpendTracker;
    sessions: SessionParamsProvider;
    fundingState?: SessionFundingStateProvider;
    epochProvider?: () => bigint;
  }) {
    this.wallet = opts.wallet;
    this.policyState = opts.policyState;
    this.spendTracker = opts.spendTracker;
    this.sessions = opts.sessions;
    this.fundingState = opts.fundingState;
    this.epochProvider = opts.epochProvider;
  }

  requiredEscrow(sessionParams: SessionParams): bigint {
    return requiredEscrow(sessionParams);
  }

  async fundNextEpoch(ghostId: Hex, sessionId: bigint): Promise<bigint> {
    const epoch = this.epochProvider?.();
    const stAny = this.spendTracker as any;
    if (epoch !== undefined && typeof stAny.loadEpoch === 'function') stAny.loadEpoch(epoch);

    const params = await this.sessions.getSessionParams(sessionId);
    const amount = requiredEscrow(params);

    const policy = await this.policyState.getCurrentPolicy(ghostId);
    if (!this.spendTracker.canSpend(amount, policy)) throw new HotAllowanceExceeded();

    const balance = await this.wallet.getBalance(ghostId);
    if (amount > balance) throw new InsufficientBalance();

    const postSpendBalance = balance - amount;
    if (!this.spendTracker.verifyEscapeReserves(policy, postSpendBalance)) {
      throw new EscapeReservesViolation();
    }

    await this.wallet.fundNextEpoch(ghostId, amount);
    this.spendTracker.recordSpend(amount);
    return amount;
  }

  async autoFundIfNeeded(ghostId: Hex): Promise<boolean> {
    if (!this.fundingState) return false;

    const epoch = this.epochProvider?.();
    const stAny = this.spendTracker as any;
    if (epoch !== undefined && typeof stAny.loadEpoch === 'function') stAny.loadEpoch(epoch);

    const auto = await this.fundingState.autoRenewLease(ghostId);
    if (!auto) return false;

    const funded = await this.fundingState.isNextEpochFunded(ghostId);
    if (funded) return false;

    const sessionId = await this.fundingState.getActiveSessionId(ghostId);
    if (sessionId === null) return false;

    await this.fundNextEpoch(ghostId, sessionId);
    return true;
  }
}
