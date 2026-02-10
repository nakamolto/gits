import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { hexToBytes, keccak256, type Hex } from 'viem';

import { decrypt } from '../vaulting/encryptor.js';
import { decodeShare, reconstructVaultKey, type ShamirShare } from '../vaulting/shamir.js';

export interface GhostRegistryLike {
  getGhost(ghostId: Hex): Promise<{
    ghost_id: Hex;
    recovery_config: { recovery_set: Hex[]; threshold: bigint };
    checkpoint_commitment: Hex;
    envelope_commitment: Hex;
    ptr_checkpoint: Hex;
    ptr_envelope: Hex;
    checkpoint_epoch: bigint;
  }>;
}

export interface GhostWalletLike {
  exitRecovery(ghostId: Hex): Promise<void>;
}

export interface TeeVerifier {
  assertIsSafeHaven(): Promise<void>;
}

export interface RecoveryShareClient {
  requestShare(args: {
    ghost_id: Hex;
    attempt_id: bigint;
    checkpoint_commitment: Hex;
    envelope_commitment: Hex;
    shell_id: Hex;
  }): Promise<Uint8Array | ShamirShare>;
}

export interface IdentityKeyStore {
  // New identity key set during recoveryRotate.
  loadIdentityPrivateKey(): Promise<Uint8Array>;
}

function ptrFromHex(ptr: Hex): string {
  return new TextDecoder().decode(hexToBytes(ptr));
}

function parseVaultBlob(blob: Uint8Array): { nonce: Uint8Array; tag: Uint8Array; ciphertext: Uint8Array } {
  if (blob.length < 1 + 12 + 16) throw new Error('InvalidVaultBlob');
  const version = blob[0];
  if (version !== 1) throw new Error(`UnsupportedVaultBlobVersion:${version}`);
  const nonce = blob.slice(1, 1 + 12);
  const tag = blob.slice(1 + 12, 1 + 12 + 16);
  const ciphertext = blob.slice(1 + 12 + 16);
  return { nonce, tag, ciphertext };
}

export class RecoveryClient {
  constructor(
    private readonly deps: {
      ghostRegistry: GhostRegistryLike;
      ghostWallet: GhostWalletLike;
      tee: TeeVerifier;
      shares: RecoveryShareClient;
      keys: IdentityKeyStore;
    },
  ) {}

  async bootFromRecovery(args: { ghost_id: Hex; attempt_id: bigint; agentDataDir: string }): Promise<void> {
    // 1) Load the new identity private key (presence is a sanity check in v1).
    await this.deps.keys.loadIdentityPrivateKey();

    // 2) Load on-chain recovery config + latest checkpoint pointers.
    const ghost = await this.deps.ghostRegistry.getGhost(args.ghost_id);
    const threshold = Number(ghost.recovery_config.threshold);
    const recovery_set = ghost.recovery_config.recovery_set;

    // 3) Request shares until we have t unique.
    const got: ShamirShare[] = [];
    const seen = new Set<number>();
    for (const shell_id of recovery_set) {
      if (got.length >= threshold) break;
      const res = await this.deps.shares.requestShare({
        ghost_id: args.ghost_id,
        attempt_id: args.attempt_id,
        checkpoint_commitment: ghost.checkpoint_commitment,
        envelope_commitment: ghost.envelope_commitment,
        shell_id,
      });

      const share: ShamirShare =
        res instanceof Uint8Array ? decodeShare(res) : { index: res.index, data: res.data };
      if (seen.has(share.index)) continue;
      seen.add(share.index);
      got.push(share);
    }

    if (got.length < threshold) throw new Error(`InsufficientShares:${got.length}:${threshold}`);

    const vaultKey = reconstructVaultKey(got, threshold);

    // 4) Fetch + verify checkpoint + envelope.
    const checkpointPath = ptrFromHex(ghost.ptr_checkpoint);
    const envelopePath = ptrFromHex(ghost.ptr_envelope);

    const vaultBlob = new Uint8Array(await readFile(checkpointPath));
    const envelopeBytes = new Uint8Array(await readFile(envelopePath));

    if (keccak256(vaultBlob) !== ghost.checkpoint_commitment) throw new Error('CheckpointCommitmentMismatch');
    if (keccak256(envelopeBytes) !== ghost.envelope_commitment) throw new Error('EnvelopeCommitmentMismatch');

    const envelope = JSON.parse(new TextDecoder().decode(envelopeBytes)) as { compressed?: boolean };

    // 5) Decrypt and restore state.
    const parsed = parseVaultBlob(vaultBlob);
    const plaintext = decrypt({ ciphertext: parsed.ciphertext, nonce: parsed.nonce, tag: parsed.tag }, vaultKey);
    const restored = envelope.compressed ? gunzipSync(plaintext) : plaintext;

    await mkdir(args.agentDataDir, { recursive: true });
    await writeFile(`${args.agentDataDir}/state.json`, restored);

    // 6) Verify Safe Haven environment (TEC check).
    await this.deps.tee.assertIsSafeHaven();

    // 7) Exit recovery mode.
    await this.deps.ghostWallet.exitRecovery(args.ghost_id);
  }
}

