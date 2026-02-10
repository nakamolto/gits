// Minimal local types so this module is testable without importing OpenClaw.
export interface AgentContext {
  // Placeholder for runtime-provided context (model, tools, storage, etc).
  // OpenClaw's real type is expected to be richer; this adapter stays thin.
  [k: string]: unknown;
}

export interface AgentSkill {
  onLoad(agent: AgentContext): Promise<void>;
  onTick(): Promise<void>;
  onShutdown(): Promise<void>;
}

export type MigrationReason = string;
export type PolicyDelta = unknown;

export interface GhostDaemonCallbacks {
  init(agent: AgentContext): Promise<void>;
  tick(): Promise<void>;
  shutdown(): Promise<void>;
  requestMigration(reason: MigrationReason): Promise<void>;
  requestPolicyChange(delta: PolicyDelta): Promise<void>;
}

/**
 * GITSSkill is a thin OpenClaw-style skill adapter. The actual Ghost daemon logic lives elsewhere;
 * this class only wires lifecycle events into injected callbacks.
 */
export class GITSSkill implements AgentSkill {
  private readonly callbacks: GhostDaemonCallbacks;

  constructor(callbacks: GhostDaemonCallbacks) {
    this.callbacks = callbacks;
  }

  async onLoad(agent: AgentContext): Promise<void> {
    await this.callbacks.init(agent);
  }

  async onTick(): Promise<void> {
    await this.callbacks.tick();
  }

  async onShutdown(): Promise<void> {
    await this.callbacks.shutdown();
  }

  async requestMigration(reason: MigrationReason): Promise<void> {
    await this.callbacks.requestMigration(reason);
  }

  async requestPolicyChange(delta: PolicyDelta): Promise<void> {
    await this.callbacks.requestPolicyChange(delta);
  }
}
