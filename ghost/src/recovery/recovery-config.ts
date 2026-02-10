import type { Address, Hex } from 'viem';

export type RecoveryConfig = {
  recovery_set: Hex[];
  threshold: bigint;
  bounty_asset: Address;
  bounty_total: bigint;
  bps_initiator: bigint;
};

export interface GhostRegistryLike {
  getGhost(ghostId: Hex): Promise<{ recovery_config: RecoveryConfig }>;
  setRecoveryConfig(ghostId: Hex, recoveryConfig: RecoveryConfig): Promise<void>;
}

export interface ShellRegistryLike {
  getShell(shellId: Hex): Promise<{
    shell_id: Hex;
    bond_status: number;
    recovery_pubkey: Hex;
    safehaven_bond_amount: bigint;
  }>;
}

export class RecoveryConfigManager {
  constructor(
    private readonly deps: {
      ghostRegistry: GhostRegistryLike;
      shellRegistry: ShellRegistryLike;
    },
  ) {}

  async loadConfig(ghostId: Hex): Promise<RecoveryConfig> {
    const g = await this.deps.ghostRegistry.getGhost(ghostId);
    return g.recovery_config;
  }

  async updateRecoverySet(ghostId: Hex, shellIds: Hex[], threshold: number): Promise<void> {
    const existing = await this.loadConfig(ghostId);
    const next: RecoveryConfig = {
      ...existing,
      recovery_set: shellIds,
      threshold: BigInt(threshold),
    };
    await this.deps.ghostRegistry.setRecoveryConfig(ghostId, next);
  }

  async verifyRSMembers(shellIds: Hex[]): Promise<void> {
    for (const shellId of shellIds) {
      const s = await this.deps.shellRegistry.getShell(shellId);

      // In v1, a bonded Safe Haven is represented by a non-empty recovery_pubkey and a non-zero Safe Haven bond.
      if (!s.recovery_pubkey || s.recovery_pubkey === '0x') throw new Error(`NotSafeHaven:${shellId}`);
      if (s.safehaven_bond_amount <= 0n) throw new Error(`NotBondedSafeHaven:${shellId}`);

      // Bond status mirrors contracts: 0=bonded.
      if (s.bond_status !== 0) throw new Error(`ShellNotBonded:${shellId}`);
    }
  }
}

