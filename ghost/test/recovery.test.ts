import { describe, expect, it, vi } from 'vitest';

import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

import { encodeAbiParameters, keccak256, toBytes, toHex, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { CheckpointPublisher, FileStorageBackend } from '../src/vaulting/checkpoint-publisher.js';
import { RecoveryClient } from '../src/recovery/recovery-client.js';

function shareDigest(args: {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
}): Hex {
  const TAG_SHARE = keccak256(toBytes('GITS_SHARE'));
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [
        TAG_SHARE,
        args.chain_id,
        args.ghost_id,
        args.attempt_id,
        args.checkpoint_commitment,
        args.envelope_commitment,
      ],
    ),
  );
}

function shareAckDigest(args: {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
}): Hex {
  const TAG_SHARE_ACK = keccak256(toBytes('GITS_SHARE_ACK'));
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [
        TAG_SHARE_ACK,
        args.chain_id,
        args.ghost_id,
        args.attempt_id,
        args.checkpoint_commitment,
        args.envelope_commitment,
      ],
    ),
  );
}

function k1IdentityPubkey(addr: Address): Hex {
  const pk_bytes = encodeAbiParameters([{ type: 'address' }], [addr]);
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1n, pk_bytes]);
}

function decryptSharePayload(payload: Uint8Array, recoverySk: Uint8Array): Uint8Array {
  if (payload.length < 2 + 32 + 12 + 16) throw new Error('bad payload');
  const alg = payload[0];
  const ephLen = payload[1];
  const ephPub = payload.slice(2, 2 + ephLen);
  const nonce = payload.slice(2 + ephLen, 2 + ephLen + 12);
  const tag = payload.slice(2 + ephLen + 12, 2 + ephLen + 12 + 16);
  const ciphertext = payload.slice(2 + ephLen + 12 + 16);

  if (alg !== 1) throw new Error(`unsupported alg ${alg}`);
  const shared = x25519.getSharedSecret(recoverySk, ephPub);
  const key = hkdf(sha256, shared, utf8ToBytes('GITS_SHARE_ECDH'), new Uint8Array([]), 32);

  const aes = gcm(key, nonce);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  return aes.decrypt(sealed);
}

describe('RecoveryClient', () => {
  it('reconstructs vault key from shares and restores state from latest checkpoint', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'gits-ghost-recovery-'));
    const agentDataDir = join(tmp, 'agent');
    const dataDir = join(tmp, 'data');
    const recoveredDir = join(tmp, 'recovered');
    await mkdir(agentDataDir, { recursive: true });
    await mkdir(recoveredDir, { recursive: true });

    const originalState = JSON.stringify({ ok: true, n: 1 });
    await writeFile(join(agentDataDir, 'state.json'), originalState);

    const chain_id = 8453n;
    const ghost_id = ('0x' + '22'.repeat(32)) as Hex;
    const epoch = 99n;
    const attempt_id = epoch;
    const vaultKey = randomBytes(32);

    // Safe Havens.
    const shellAccounts = Array.from({ length: 5 }, (_, i) =>
      privateKeyToAccount((('0x' + (i + 11).toString(16).padStart(64, '0')) as Hex)),
    );
    const ackAccount = privateKeyToAccount(('0x' + 'cd'.repeat(32)) as Hex);

    const shells = new Map<Hex, { identity_pubkey: Hex; recovery_pubkey: Hex; recovery_sk: Uint8Array }>();
    const recoverySet = shellAccounts.map((acct, i) => {
      const shell_id = keccak256(toBytes(`rs-${i}`)) as Hex;
      const recovery_sk = x25519.utils.randomSecretKey();
      const recovery_pk = x25519.getPublicKey(recovery_sk);
      shells.set(shell_id, {
        identity_pubkey: k1IdentityPubkey(acct.address),
        recovery_pubkey: toHex(recovery_pk),
        recovery_sk,
      });
      return { shell_id, endpoint: `http://safehaven/${i}`, expected_ack_signer: ackAccount.address };
    });

    const shellRegistry = {
      async getShell(shellId: Hex) {
        const s = shells.get(shellId);
        if (!s) throw new Error('UnknownShell');
        return { identity_pubkey: s.identity_pubkey, recovery_pubkey: s.recovery_pubkey };
      },
    };

    // Transport decrypts the delivered share and stores it for later retrieval.
    const deliveredShares = new Map<Hex, Uint8Array>();
    const transport = {
      async sendShare(args: {
        chain_id: bigint;
        ghost_id: Hex;
        attempt_id: bigint;
        checkpoint_commitment: Hex;
        envelope_commitment: Hex;
        shell_id: Hex;
        endpoint: string;
        payload: Uint8Array;
      }) {
        const shell = shells.get(args.shell_id);
        if (!shell) throw new Error('UnknownShell');
        const shareBytes = decryptSharePayload(args.payload, shell.recovery_sk);
        deliveredShares.set(args.shell_id, shareBytes);

        const d1 = shareDigest({
          chain_id: args.chain_id,
          ghost_id: args.ghost_id,
          attempt_id: args.attempt_id,
          checkpoint_commitment: args.checkpoint_commitment,
          envelope_commitment: args.envelope_commitment,
        });
        const d2 = shareAckDigest({
          chain_id: args.chain_id,
          ghost_id: args.ghost_id,
          attempt_id: args.attempt_id,
          checkpoint_commitment: args.checkpoint_commitment,
          envelope_commitment: args.envelope_commitment,
        });
        const idx = recoverySet.findIndex((m) => m.shell_id === args.shell_id);
        const shellAccount = shellAccounts[idx];
        const sig_shell = await shellAccount.sign({ hash: d1 });
        const sig_ack = await ackAccount.sign({ hash: d2 });
        return { receipt: { shell_id: args.shell_id, sig_shell, sig_ack } };
      },
    };

    const publishCheckpoint = vi.fn(async () => undefined);
    const publisher = new CheckpointPublisher({
      shellRegistry,
      ghostRegistry: { publishCheckpoint },
      storage: new FileStorageBackend(),
      transport,
    });

    const pub = await publisher.publish({
      chain_id,
      ghost_id,
      epoch,
      attempt_id,
      agentDataDir,
      dataDir,
      compress: false,
      vaultKey,
      threshold: 3,
      recoverySet,
    });

    // Recovery client mocks.
    const ghostRegistry = {
      async getGhost(_ghostId: Hex) {
        return {
          ghost_id,
          recovery_config: { recovery_set: recoverySet.map((m) => m.shell_id), threshold: 3n },
          checkpoint_commitment: pub.checkpoint_commitment,
          envelope_commitment: pub.envelope_commitment,
          ptr_checkpoint: toHex(new TextEncoder().encode(pub.ptr_checkpoint)),
          ptr_envelope: toHex(new TextEncoder().encode(pub.ptr_envelope)),
          checkpoint_epoch: epoch,
        };
      },
    };

    const exitRecovery = vi.fn(async () => undefined);
    const tee = { assertIsSafeHaven: vi.fn(async () => undefined) };
    const keys = { loadIdentityPrivateKey: vi.fn(async () => randomBytes(32)) };
    const shares = {
      async requestShare(args: { shell_id: Hex }) {
        const s = deliveredShares.get(args.shell_id);
        if (!s) throw new Error('NoShare');
        return s;
      },
    };

    const client = new RecoveryClient({
      ghostRegistry,
      ghostWallet: { exitRecovery },
      tee,
      shares,
      keys,
    });

    await client.bootFromRecovery({ ghost_id, attempt_id, agentDataDir: recoveredDir });

    const restored = await readFile(join(recoveredDir, 'state.json'), 'utf8');
    expect(restored).toBe(originalState);
    expect(tee.assertIsSafeHaven).toHaveBeenCalledTimes(1);
    expect(exitRecovery).toHaveBeenCalledWith(ghost_id);
  });
});

