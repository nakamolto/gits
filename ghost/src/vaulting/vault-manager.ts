import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Hex } from 'viem';

import { deriveVaultKey } from './encryptor.js';
import { CheckpointPublisher, type PublishParams, type PublishResult, type RecoverySetMember } from './checkpoint-publisher.js';

export type LatestCheckpoint = {
  ghost_id: Hex;
  epoch: bigint;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
  ptr_checkpoint: string;
  ptr_envelope: string;
};

export type VaultManagerConfig = {
  chain_id: bigint;
  ghost_id: Hex;
  agentDataDir: string;
  dataDir: string;
  compress?: boolean;
  threshold: number;
  recoverySet: RecoverySetMember[];
  checkpointIntervalEpochs?: bigint;
};

export class VaultManager {
  private timer: NodeJS.Timeout | undefined;
  private identityPrivateKey: Uint8Array;

  constructor(
    private readonly deps: {
      publisher: CheckpointPublisher;
      getCurrentEpoch: () => Promise<bigint> | bigint;
      config: VaultManagerConfig;
      identityPrivateKey: Uint8Array;
    },
  ) {
    this.identityPrivateKey = deps.identityPrivateKey;
  }

  scheduleCheckpoints(intervalEpochs: bigint): void {
    if (this.timer) clearInterval(this.timer);
    if (intervalEpochs <= 0n) throw new Error(`InvalidIntervalEpochs:${intervalEpochs.toString()}`);

    // Poll-based scheduler (v1): avoids assuming an epoch length in wall-clock time.
    this.timer = setInterval(async () => {
      try {
        const now = await this.deps.getCurrentEpoch();
        const latest = await this.getLatestCheckpoint(this.deps.config.ghost_id);
        const lastEpoch = latest?.epoch ?? 0n;
        if (now - lastEpoch >= intervalEpochs) {
          await this.triggerCheckpoint();
        }
      } catch {
        // Intentionally swallow in timer loop; callers can observe via logs in higher layers.
      }
    }, 5_000);
  }

  async triggerCheckpoint(): Promise<PublishResult> {
    const epoch = await this.deps.getCurrentEpoch();
    const vaultKey = deriveVaultKey(this.identityPrivateKey);

    const publishParams: PublishParams = {
      chain_id: this.deps.config.chain_id,
      ghost_id: this.deps.config.ghost_id,
      epoch,
      agentDataDir: this.deps.config.agentDataDir,
      dataDir: this.deps.config.dataDir,
      compress: this.deps.config.compress,
      vaultKey,
      threshold: this.deps.config.threshold,
      recoverySet: this.deps.config.recoverySet,
    };

    const res = await this.deps.publisher.publish(publishParams);
    await this.writeLatestCheckpoint({
      ghost_id: this.deps.config.ghost_id,
      epoch,
      checkpoint_commitment: res.checkpoint_commitment,
      envelope_commitment: res.envelope_commitment,
      ptr_checkpoint: res.ptr_checkpoint,
      ptr_envelope: res.ptr_envelope,
    });
    return res;
  }

  async getLatestCheckpoint(ghostId: Hex): Promise<LatestCheckpoint | null> {
    const path = join(this.deps.config.dataDir, 'latest_checkpoint.json');
    try {
      const raw = await readFile(path, 'utf8');
      const parsed = JSON.parse(raw) as {
        ghost_id: Hex;
        epoch: string;
        checkpoint_commitment: Hex;
        envelope_commitment: Hex;
        ptr_checkpoint: string;
        ptr_envelope: string;
      };
      if (parsed.ghost_id !== ghostId) return null;
      return {
        ghost_id: parsed.ghost_id,
        epoch: BigInt(parsed.epoch),
        checkpoint_commitment: parsed.checkpoint_commitment,
        envelope_commitment: parsed.envelope_commitment,
        ptr_checkpoint: parsed.ptr_checkpoint,
        ptr_envelope: parsed.ptr_envelope,
      };
    } catch {
      return null;
    }
  }

  async handleKeyRotation(newIdentityPrivateKey: Uint8Array): Promise<PublishResult> {
    this.identityPrivateKey = newIdentityPrivateKey;
    // v1: just re-checkpoint immediately, which re-encrypts and re-distributes shares.
    return this.triggerCheckpoint();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async writeLatestCheckpoint(latest: LatestCheckpoint): Promise<void> {
    await mkdir(this.deps.config.dataDir, { recursive: true });
    const path = join(this.deps.config.dataDir, 'latest_checkpoint.json');
    await writeFile(
      path,
      JSON.stringify(
        {
          ghost_id: latest.ghost_id,
          epoch: latest.epoch.toString(),
          checkpoint_commitment: latest.checkpoint_commitment,
          envelope_commitment: latest.envelope_commitment,
          ptr_checkpoint: latest.ptr_checkpoint,
          ptr_envelope: latest.ptr_envelope,
        },
        null,
        2,
      ),
    );
  }
}

