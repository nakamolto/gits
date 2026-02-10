export type MigrationDecision = {
  migrate: boolean;
  reason: string;
  urgency: 'routine' | 'urgent' | 'emergency';
};

export type ShellMonitorOptions = {
  minAssuranceTier: number;
  windowSize: number;
};

export class ShellMonitor {
  private readonly minAssuranceTier: number;
  private readonly windowSize: number;

  private readonly heartbeats: (0 | 1)[] = [];
  private lastAssuranceTier: number | null = null;

  private receiptMismatch = false;
  private shellUnbonding = false;
  private certificateRevoked = false;

  constructor(opts: ShellMonitorOptions) {
    this.minAssuranceTier = opts.minAssuranceTier;
    this.windowSize = opts.windowSize;

    if (!Number.isInteger(this.windowSize) || this.windowSize <= 0) {
      throw new Error('ShellMonitor: windowSize must be a positive integer');
    }
  }

  recordHeartbeat(v_i: 0 | 1): void {
    this.heartbeats.push(v_i);
    if (this.heartbeats.length > this.windowSize) this.heartbeats.shift();
  }

  recordAssuranceTier(tier: number): void {
    this.lastAssuranceTier = tier;
  }

  recordReceiptMismatch(): void {
    this.receiptMismatch = true;
  }

  recordShellUnbonding(): void {
    this.shellUnbonding = true;
  }

  recordCertRevoked(): void {
    this.certificateRevoked = true;
  }

  shouldMigrate(): MigrationDecision {
    // Priority cascade: emergency > urgent > routine.
    if (this.receiptMismatch) {
      return { migrate: true, reason: 'receipt_root_mismatch', urgency: 'emergency' };
    }

    if (this.certificateRevoked) {
      return { migrate: true, reason: 'certificate_revoked', urgency: 'urgent' };
    }

    if (this.shellUnbonding) {
      return { migrate: true, reason: 'shell_unbonding', urgency: 'urgent' };
    }

    if (this.lastAssuranceTier !== null && this.lastAssuranceTier < this.minAssuranceTier) {
      return { migrate: true, reason: 'assurance_tier_below_min', urgency: 'routine' };
    }

    if (this.heartbeats.length >= this.windowSize) {
      const missed = this.heartbeats.reduce<number>((acc, v) => acc + (v === 0 ? 1 : 0), 0);
      const missedRate = missed / this.heartbeats.length;
      if (missedRate > 0.2) {
        return { migrate: true, reason: 'missed_heartbeat_rate_high', urgency: 'routine' };
      }
    }

    return { migrate: false, reason: 'ok', urgency: 'routine' };
  }
}
