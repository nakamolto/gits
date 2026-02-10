import type { Hex } from 'viem';

export type EpochTicker = {
  onEpoch(cb: (epoch: bigint) => void): () => void;
};

export type LeaseSession = {
  ghost_id: Hex;
  shell_id: Hex;
  lease_expiry_epoch: bigint;
  tenure_limit_epochs: bigint;
  session_start_epoch: bigint;
};

export type LeaseManagerOptions = {
  migrationBufferEpochs: bigint;
  autoRenewLease: boolean;
  epochTicker: EpochTicker;
  renewLease: (ghost_id: Hex) => Promise<void>;
  isRefreshAnchor: (ghost_id: Hex, shell_id: Hex) => Promise<boolean>;
  planMigration: (reason: string, urgency: 'routine' | 'urgent' | 'emergency') => void;
};

export class LeaseManager {
  private readonly migrationBufferEpochs: bigint;
  private readonly autoRenewLease: boolean;
  private readonly epochTicker: EpochTicker;
  private readonly renewLease: (ghost_id: Hex) => Promise<void>;
  private readonly isRefreshAnchor: (ghost_id: Hex, shell_id: Hex) => Promise<boolean>;
  private readonly planMigration: (reason: string, urgency: 'routine' | 'urgent' | 'emergency') => void;

  private unsubscribe: (() => void) | null = null;
  private session: LeaseSession | null = null;
  private lastLeaseAttemptEpoch: bigint | null = null;
  private lastTenureSignalEpoch: bigint | null = null;

  constructor(opts: LeaseManagerOptions) {
    this.migrationBufferEpochs = opts.migrationBufferEpochs;
    this.autoRenewLease = opts.autoRenewLease;
    this.epochTicker = opts.epochTicker;
    this.renewLease = opts.renewLease;
    this.isRefreshAnchor = opts.isRefreshAnchor;
    this.planMigration = opts.planMigration;

    if (this.migrationBufferEpochs < 0n) {
      throw new Error('LeaseManager: migrationBufferEpochs must be >= 0');
    }
  }

  start(session: LeaseSession): void {
    this.stop();
    this.session = session;
    this.unsubscribe = this.epochTicker.onEpoch((epoch) => {
      void this.onEpoch(epoch);
    });
  }

  stop(): void {
    if (this.unsubscribe) this.unsubscribe();
    this.unsubscribe = null;
    this.session = null;
    this.lastLeaseAttemptEpoch = null;
    this.lastTenureSignalEpoch = null;
  }

  private async onEpoch(epoch: bigint): Promise<void> {
    const s = this.session;
    if (!s) return;

    const leaseRenewAt = s.lease_expiry_epoch > this.migrationBufferEpochs ? s.lease_expiry_epoch - this.migrationBufferEpochs : 0n;

    if (epoch >= leaseRenewAt && this.lastLeaseAttemptEpoch !== epoch) {
      this.lastLeaseAttemptEpoch = epoch;

      if (!this.autoRenewLease) {
        this.planMigration('lease_expiry_approaching', 'routine');
      } else {
        try {
          const eligible = await this.isRefreshAnchor(s.ghost_id, s.shell_id);
          if (!eligible) {
            this.planMigration('trust_refresh_ineligible', 'routine');
          } else {
            await this.renewLease(s.ghost_id);
          }
        } catch {
          this.planMigration('renew_lease_failed', 'routine');
        }
      }
    }

    const tenureEnd = s.session_start_epoch + s.tenure_limit_epochs;
    const tenureSignalAt = tenureEnd > this.migrationBufferEpochs ? tenureEnd - this.migrationBufferEpochs : 0n;

    if (epoch >= tenureSignalAt && this.lastTenureSignalEpoch !== epoch) {
      this.lastTenureSignalEpoch = epoch;
      this.planMigration('tenure_expiring', 'routine');
    }
  }
}
