import type { Policy } from '@gits-protocol/sdk';

export interface SpendStore {
  getSpentThisEpoch(ghostId: Uint8Array, epoch: number): bigint;
  setSpentThisEpoch(ghostId: Uint8Array, epoch: number, amount: bigint): void;
}

export class EscapeReservesViolation extends Error {
  constructor() {
    super('Escape reserves would be violated');
  }
}

export class SpendTracker {
  private _spentThisEpoch: bigint = 0n;
  private _currentEpoch: bigint = -1n;

  constructor(
    private readonly store?: SpendStore,
    private readonly ghostIdBytes?: Uint8Array,
  ) {}

  get spentThisEpoch(): bigint {
    return this._spentThisEpoch;
  }

  get currentEpoch(): bigint {
    return this._currentEpoch;
  }

  /** Load spend state for an epoch (from DB or reset to 0). */
  loadEpoch(epoch: bigint): void {
    if (epoch === this._currentEpoch) return;
    this._currentEpoch = epoch;

    if (this.store && this.ghostIdBytes) {
      this._spentThisEpoch = this.store.getSpentThisEpoch(this.ghostIdBytes, Number(epoch));
    } else {
      this._spentThisEpoch = 0n;
    }
  }

  canSpend(amount: bigint, policy: Policy): boolean {
    if (amount < 0n) throw new RangeError('amount must be >= 0');
    return this._spentThisEpoch + amount <= policy.hot_allowance;
  }

  recordSpend(amount: bigint): void {
    if (amount < 0n) throw new RangeError('amount must be >= 0');
    this._spentThisEpoch += amount;
    this.persist();
  }

  resetEpoch(): void {
    this._spentThisEpoch = 0n;
    this.persist();
  }

  // Escape reserves are SACRED: callers must pass the post-spend wallet balance.
  verifyEscapeReserves(policy: Policy, walletBalance: bigint): boolean {
    return walletBalance >= policy.escape_gas + policy.escape_stable + this._spentThisEpoch;
  }

  private persist(): void {
    if (this.store && this.ghostIdBytes && this._currentEpoch >= 0n) {
      this.store.setSpentThisEpoch(this.ghostIdBytes, Number(this._currentEpoch), this._spentThisEpoch);
    }
  }
}
