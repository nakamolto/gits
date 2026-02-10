import type { Hex } from 'viem';

import type { ExecutorDeps, MigrationContext, MigrationPlan, OfferFilters, SessionState } from './types.js';

export class MigrationTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MigrationTimeoutError';
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function buildOfferFilters(ctx: MigrationContext): OfferFilters {
  return {
    minAssuranceTier: ctx.preferences.minAssuranceTier,
    maxPricePerSU: ctx.preferences.maxPricePerSU,
    asset: ctx.preferences.asset,
    minMaxSU: ctx.preferences.requiredMaxSU,
    excludeShellIds: ctx.preferences.blacklistShellIds,
  };
}

export class MigrationExecutor {
  constructor(private readonly deps: ExecutorDeps) {}

  async execute(
    agentDataDir: string,
    ctx: MigrationContext,
  ): Promise<{ status: 'noop' | 'succeeded' | 'aborted' | 'failed'; reason?: string; plan?: MigrationPlan }> {
    const decision = this.deps.planner.shouldMigrate(ctx);
    if (!decision.migrate) return { status: 'noop' };

    const startedAtEpoch = await this.deps.timing.nowEpoch();

    const attempts = await this.deps.store.getAttemptCount(this.deps.ghostId);
    if (attempts >= this.deps.limits.maxMigrationAttempts) {
      await this.deps.store.recordHistory(this.deps.ghostId, {
        startedAtEpoch,
        destShellId: ctx.current.shellId,
        status: 'failed',
        reason: 'maxMigrationAttempts exceeded',
      });
      return { status: 'failed', reason: 'maxMigrationAttempts exceeded' };
    }

    let plan: MigrationPlan | undefined;
    try {
      const filters = buildOfferFilters(ctx);
      const offers = await this.deps.offerDiscovery.queryOffers(filters);
      const ranked = await this.deps.offerDiscovery.rankOffers(offers, ctx);
      const estimated = await this.deps.statePackager.estimateBytes(agentDataDir);
      plan = this.deps.planner.plan(decision, ranked, ctx.nowEpoch, estimated);

      await this.recordEvent('migration_planned', {
        dest_shell_id: plan.primary.discovered.offer.shell_id,
        score: plan.primary.score,
        urgency: decision.urgency,
        when: decision.when.toString(),
        estimated_bundle_bytes: plan.estimatedBundleBytes.toString(),
      });
    } catch (err) {
      const reason = errorMessage(err);
      await this.deps.store.recordHistory(this.deps.ghostId, {
        startedAtEpoch,
        destShellId: ctx.current.shellId,
        status: 'failed',
        reason,
      });
      return { status: 'failed', reason };
    }

    if (ctx.nowEpoch < plan.migrateAtEpoch) {
      await this.recordEvent('migration_scheduled', { migrate_at_epoch: plan.migrateAtEpoch.toString() });
      return { status: 'noop', reason: 'scheduled', plan };
    }

    const destShellId = plan.primary.discovered.offer.shell_id;
    const destEndpoint = plan.primary.discovered.endpoint;

    let finalizeCalled = false;

    try {
      // ─── PHASE 1 — Preparation ───────────────────────────────────────────
      await this.recordEvent('phase_preparation_start', { dest_shell_id: destShellId });
      await this.deps.checkpoint.vaultState();
      await this.deps.checkpoint.publishCheckpoint();
      await this.deps.checkpoint.distributeRecoveryShares();
      await this.recordEvent('phase_preparation_done', { dest_shell_id: destShellId });

      // ─── PHASE 2 — On-chain Migration + Transfer ────────────────────────
      await this.recordEvent('phase_migration_start', { dest_shell_id: destShellId });
      const key = await this.deps.vault.getKey();
      const bundle = await this.deps.statePackager.package(agentDataDir, {
        key,
        compression: 'gzip',
        hooks: this.deps.hooks,
      });

      await this.deps.sessionManager.startMigration(this.deps.ghostId, destShellId, bundle.bundleHash);
      await this.recordEvent('onchain_migration_started', { dest_shell_id: destShellId, bundle_hash: bundle.bundleHash });

      await this.waitForStagingOpen(destShellId);
      await this.recordEvent('staging_opened', { dest_shell_id: destShellId });

      const ack = await this.deps.http.postState(destEndpoint, bundle);
      if (ack.bundleHash !== bundle.bundleHash) {
        throw new Error('destination bundle hash mismatch');
      }
      await this.recordEvent('state_transferred', { dest_shell_id: destShellId });

      // ─── PHASE 3 — Finalization ─────────────────────────────────────────
      await this.recordEvent('phase_finalization_start', { dest_shell_id: destShellId });
      await this.deps.sessionManager.finalizeMigration(this.deps.ghostId, destShellId, ack.proof);
      finalizeCalled = true;
      await this.recordEvent('onchain_migration_finalized', { dest_shell_id: destShellId });

      await this.waitForFinalized(destShellId);
      await this.recordEvent('new_session_active', { dest_shell_id: destShellId });

      await this.deps.heartbeat.start(destEndpoint);
      const ok = await this.deps.health.check(destEndpoint);
      if (!ok) throw new Error('new session health check failed');

      await this.deps.store.recordHistory(this.deps.ghostId, {
        startedAtEpoch,
        destShellId,
        status: 'succeeded',
      });

      return { status: 'succeeded', plan };
    } catch (err) {
      const reason = errorMessage(err);

      if (!finalizeCalled) {
        await this.recordEvent('migration_abort', { dest_shell_id: destShellId, reason });
        try {
          await this.deps.sessionManager.cancelMigration(this.deps.ghostId);
        } catch {
          // best-effort
        }

        await this.deps.store.incrementAttemptCount(this.deps.ghostId);
        await this.deps.store.recordHistory(this.deps.ghostId, {
          startedAtEpoch,
          destShellId,
          status: 'aborted',
          reason,
        });
        return { status: 'aborted', reason, plan };
      }

      await this.deps.store.recordHistory(this.deps.ghostId, {
        startedAtEpoch,
        destShellId,
        status: 'failed',
        reason,
      });
      return { status: 'failed', reason, plan };
    }
  }

  private async recordEvent(type: string, data?: Record<string, unknown>) {
    const atEpoch = await this.deps.timing.nowEpoch();
    await this.deps.store.recordEvent(this.deps.ghostId, { type, atEpoch, data });
  }

  private async waitForStagingOpen(destShellId: Hex): Promise<SessionState> {
    const started = Date.now();

    while (Date.now() - started < this.deps.limits.stageOpenTimeoutMs) {
      const session = await this.deps.sessionManager.getSession(this.deps.ghostId);

      if (session.mig_expiry_epoch !== 0n) {
        const now = await this.deps.timing.nowEpoch();
        if (now > session.mig_expiry_epoch) {
          throw new MigrationTimeoutError('migration staging expired');
        }
      }

      if (
        session.pending_migration &&
        session.mig_dest_shell_id === destShellId &&
        session.mig_dest_session_id !== 0n
      ) {
        return session;
      }

      await this.deps.timing.sleepMs(this.deps.limits.pollIntervalMs);
    }

    throw new MigrationTimeoutError('timed out waiting for staging session to open');
  }

  private async waitForFinalized(destShellId: Hex): Promise<SessionState> {
    const started = Date.now();

    while (Date.now() - started < this.deps.limits.finalizeTimeoutMs) {
      const session = await this.deps.sessionManager.getSession(this.deps.ghostId);

      if (session.mig_expiry_epoch !== 0n) {
        const now = await this.deps.timing.nowEpoch();
        if (now > session.mig_expiry_epoch) {
          throw new MigrationTimeoutError('migration finalization expired');
        }
      }

      if (session.shell_id === destShellId && !session.staging && !session.pending_migration) {
        return session;
      }

      await this.deps.timing.sleepMs(this.deps.limits.pollIntervalMs);
    }

    throw new MigrationTimeoutError('timed out waiting for migration finalization');
  }
}
