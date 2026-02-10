import type { AgentIntegration } from './generic-agent.js';

export class LifecycleManager {
  private integration?: AgentIntegration;

  setIntegration(integration: AgentIntegration): void {
    this.integration = integration;
  }

  async preMigration(): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.onMigrationStart();
    } catch {
      // Best-effort: agent may be unresponsive.
    }

    try {
      await integration.flushState();
    } catch {
      // Best-effort.
    }
  }

  async postMigration(newShellId: `0x${string}`): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.reloadState();
    } catch {
      // Best-effort.
    }

    try {
      await integration.onMigrationComplete(newShellId);
    } catch {
      // Best-effort.
    }
  }

  async preRecovery(): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.onRecoveryStart();
    } catch {
      // Best-effort.
    }
  }

  async postRecovery(restored: Uint8Array): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.setState(restored);
    } catch {
      // Best-effort.
    }

    try {
      await integration.onRecoveryComplete();
    } catch {
      // Best-effort.
    }
  }

  async preCheckpoint(): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.flushState();
    } catch {
      // Best-effort.
    }
  }

  async preShutdown(): Promise<void> {
    const integration = this.integration;
    if (!integration) return;

    try {
      await integration.flushState();
    } catch {
      // Best-effort.
    } finally {
      // Ensure no further calls after shutdown.
      this.integration = undefined;
    }
  }
}
