import type { Policy } from '../../../sdk/src/types/structs.js';

export class EscapeReservesViolation extends Error {
  constructor() {
    super('Escape reserves would be violated');
  }
}

export class SpendTracker {
  private _spentThisEpoch: bigint = 0n;

  get spentThisEpoch(): bigint {
    return this._spentThisEpoch;
  }

  canSpend(amount: bigint, policy: Policy): boolean {
    if (amount < 0n) throw new RangeError('amount must be >= 0');
    return this._spentThisEpoch + amount <= policy.hot_allowance;
  }

  recordSpend(amount: bigint): void {
    if (amount < 0n) throw new RangeError('amount must be >= 0');
    this._spentThisEpoch += amount;
  }

  resetEpoch(): void {
    this._spentThisEpoch = 0n;
  }

  // Escape reserves are SACRED: callers must pass the post-spend wallet balance.
  verifyEscapeReserves(policy: Policy, walletBalance: bigint): boolean {
    return walletBalance >= policy.escape_gas + policy.escape_stable + this._spentThisEpoch;
  }
}
