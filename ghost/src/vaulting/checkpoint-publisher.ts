import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  decodeAbiParameters,
  encodeAbiParameters,
  hexToBytes,
  keccak256,
  recoverAddress,
  toBytes,
  toHex,
  type Address,
  type Hex,
} from 'viem';

import { encrypt, type EncryptedVault } from './encryptor.js';
import { encodeShare, splitVaultKey, type ShamirShare } from './shamir.js';

export type ShareReceipt = {
  shell_id: Hex;
  sig_shell: Hex;
  sig_ack: Hex;
};

export type RecoverySetMember = {
  shell_id: Hex;
  endpoint: string;
  // Optional expected signer address for the Recovery VM ack signature.
  expected_ack_signer?: Address;
};

export interface ShellRegistryLike {
  getShell(shellId: Hex): Promise<{ identity_pubkey: Hex; recovery_pubkey: Hex }>;
}

export interface GhostRegistryLike {
  publishCheckpoint(
    ghostId: Hex,
    epoch: bigint,
    checkpointCommitment: Hex,
    envelopeCommitment: Hex,
    ptrCheckpoint: Hex,
    ptrEnvelope: Hex,
  ): Promise<void>;
}

export interface StorageBackend {
  putBlob(path: string, bytes: Uint8Array): Promise<string>;
}

export interface SafeHavenTransport {
  sendShare(args: {
    chain_id: bigint;
    ghost_id: Hex;
    attempt_id: bigint;
    checkpoint_commitment: Hex;
    envelope_commitment: Hex;
    shell_id: Hex;
    endpoint: string;
    payload: Uint8Array;
  }): Promise<{ receipt: ShareReceipt }>;
}

export type PublishParams = {
  chain_id: bigint;
  ghost_id: Hex;
  epoch: bigint;
  // Used for receipt digests; checkpoints are outside recovery attempts so we default to epoch.
  attempt_id?: bigint;

  agentDataDir: string;
  dataDir: string;
  compress?: boolean;

  vaultKey: Uint8Array;
  threshold: number;
  recoverySet: RecoverySetMember[];
};

export type PublishResult = {
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
  ptr_checkpoint: string;
  ptr_envelope: string;
  share_receipts: ShareReceipt[];
};

export class FileStorageBackend implements StorageBackend {
  async putBlob(path: string, bytes: Uint8Array): Promise<string> {
    const dir = dirname(path);
    await mkdir(dir, { recursive: true });
    await writeFile(path, bytes);
    return path;
  }
}

function encodeVaultBlob(vault: EncryptedVault): Uint8Array {
  // v1 wire format: version(1) || nonce(12) || tag(16) || ciphertext
  if (vault.nonce.length !== 12) throw new Error(`InvalidNonceLength:${vault.nonce.length}`);
  if (vault.tag.length !== 16) throw new Error(`InvalidTagLength:${vault.tag.length}`);
  const out = new Uint8Array(1 + 12 + 16 + vault.ciphertext.length);
  out[0] = 1;
  out.set(vault.nonce, 1);
  out.set(vault.tag, 1 + 12);
  out.set(vault.ciphertext, 1 + 12 + 16);
  return out;
}

function shareDigest(args: {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  envelope_commitment: Hex;
}): Hex {
  const TAG_SHARE = keccak256(toBytes('GITS_SHARE'));
  const { chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment } = args;
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
      [TAG_SHARE, chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment],
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
  const { chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment } = args;
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
      [TAG_SHARE_ACK, chain_id, ghost_id, attempt_id, checkpoint_commitment, envelope_commitment],
    ),
  );
}

function decodeIdentityK1Address(identity_pubkey: Hex): Address {
  const [sig_alg, pk_bytes] = decodeAbiParameters(
    [{ type: 'uint8' }, { type: 'bytes' }],
    identity_pubkey,
  ) as unknown as [number, Hex];
  if (sig_alg !== 1) throw new Error(`UnsupportedSigAlg:${sig_alg}`);
  const [addr] = decodeAbiParameters([{ type: 'address' }], pk_bytes) as unknown as [Address];
  return addr;
}

function ptrToHex(ptr: string): Hex {
  return toHex(new TextEncoder().encode(ptr));
}

type EncryptedSharePayload = {
  alg_id: number; // 1=x25519, 2=secp256k1
  eph_pubkey: Uint8Array;
  nonce: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
};

function encryptShareToRecoveryPubkey(shareBytes: Uint8Array, recovery_pubkey: Uint8Array): EncryptedSharePayload {
  const nonce = randomBytes(12);

  let alg_id = 0;
  let eph_priv: Uint8Array;
  let eph_pub: Uint8Array;
  let shared: Uint8Array;

  if (recovery_pubkey.length === 32) {
    alg_id = 1;
    eph_priv = x25519.utils.randomSecretKey();
    eph_pub = x25519.getPublicKey(eph_priv);
    shared = x25519.getSharedSecret(eph_priv, recovery_pubkey);
  } else if (recovery_pubkey.length === 33 || recovery_pubkey.length === 65) {
    alg_id = 2;
    eph_priv = secp256k1.utils.randomSecretKey();
    eph_pub = secp256k1.getPublicKey(eph_priv, true);
    shared = secp256k1.getSharedSecret(eph_priv, recovery_pubkey);
  } else {
    throw new Error(`UnsupportedRecoveryPubkeyLength:${recovery_pubkey.length}`);
  }

  const salt = utf8ToBytes('GITS_SHARE_ECDH');
  const info = new Uint8Array([]);
  const key = hkdf(sha256, shared, salt, info, 32);

  const aes = gcm(key, nonce);
  const sealed = aes.encrypt(shareBytes); // ciphertext || tag
  const tag = sealed.slice(sealed.length - 16);
  const ciphertext = sealed.slice(0, sealed.length - 16);

  return { alg_id, eph_pubkey: eph_pub, nonce, tag, ciphertext };
}

function encodeEncryptedSharePayload(p: EncryptedSharePayload): Uint8Array {
  if (p.nonce.length !== 12) throw new Error(`InvalidNonceLength:${p.nonce.length}`);
  if (p.tag.length !== 16) throw new Error(`InvalidTagLength:${p.tag.length}`);
  if (p.eph_pubkey.length > 255) throw new Error(`EphemeralPubkeyTooLong:${p.eph_pubkey.length}`);

  const out = new Uint8Array(1 + 1 + p.eph_pubkey.length + 12 + 16 + p.ciphertext.length);
  let o = 0;
  out[o++] = p.alg_id & 0xff;
  out[o++] = p.eph_pubkey.length & 0xff;
  out.set(p.eph_pubkey, o);
  o += p.eph_pubkey.length;
  out.set(p.nonce, o);
  o += 12;
  out.set(p.tag, o);
  o += 16;
  out.set(p.ciphertext, o);
  return out;
}

export class CheckpointPublisher {
  constructor(
    private readonly deps: {
      shellRegistry: ShellRegistryLike;
      ghostRegistry: GhostRegistryLike;
      storage: StorageBackend;
      transport: SafeHavenTransport;
    },
  ) {}

  async publish(params: PublishParams): Promise<PublishResult> {
    const attempt_id = params.attempt_id ?? params.epoch;
    const members = [...params.recoverySet].sort((a, b) => (a.shell_id < b.shell_id ? -1 : a.shell_id > b.shell_id ? 1 : 0));

    // 1) Serialize agent state.
    const statePath = join(params.agentDataDir, 'state.json');
    const stateBytes = new Uint8Array(await readFile(statePath));

    // 2) Compress if enabled.
    const payload = params.compress ? gzipSync(stateBytes) : stateBytes;

    // 3) Encrypt with vault key.
    const vault = encrypt(payload, params.vaultKey);
    const vaultBlob = encodeVaultBlob(vault);

    // 4) checkpoint_commitment.
    const checkpoint_commitment = keccak256(vaultBlob);

    // 5) Split vault key into Shamir shares.
    const shares = splitVaultKey(params.vaultKey, params.threshold, members.length);

    // 6) envelope_commitment over deterministic metadata.
    const shareHashes = shares
      .map((s) => ({
        index: s.index,
        share_hash: keccak256(encodeShare(s)),
      }))
      .sort((a, b) => a.index - b.index);

    const envelopeMeta = {
      version: 1,
      ghost_id: params.ghost_id,
      epoch: params.epoch.toString(),
      compressed: !!params.compress,
      threshold: params.threshold,
      total_shares: members.length,
      checkpoint_commitment,
      shares: shareHashes,
    };
    const envelopeBytes = new TextEncoder().encode(JSON.stringify(envelopeMeta));
    const envelope_commitment = keccak256(envelopeBytes);

    // 7) Store checkpoint + envelope locally (v1 storage backend).
    const base = join(params.dataDir, 'checkpoints', params.ghost_id, params.epoch.toString());
    const ptr_checkpoint = await this.deps.storage.putBlob(`${base}.vault`, vaultBlob);
    const ptr_envelope = await this.deps.storage.putBlob(`${base}.envelope.json`, envelopeBytes);

    // 8-9) Distribute shares and collect receipts.
    const receipts: ShareReceipt[] = [];
    const distributionLog: unknown[] = [];

    for (let i = 0; i < members.length; i++) {
      const member = members[i];
      const share = shares[i];
      if (share.index !== i + 1) throw new Error('UnexpectedShareIndex');

      const shell = await this.deps.shellRegistry.getShell(member.shell_id);
      const recoveryPubkey = hexToBytes(shell.recovery_pubkey);
      const shareBytes = encodeShare(share);

      const encrypted = encryptShareToRecoveryPubkey(shareBytes, recoveryPubkey);
      const payloadBytes = encodeEncryptedSharePayload(encrypted);

      const { receipt } = await this.deps.transport.sendShare({
        chain_id: params.chain_id,
        ghost_id: params.ghost_id,
        attempt_id,
        checkpoint_commitment,
        envelope_commitment,
        shell_id: member.shell_id,
        endpoint: member.endpoint,
        payload: payloadBytes,
      });

      if (receipt.shell_id !== member.shell_id) throw new Error('ReceiptShellIdMismatch');

      // Verify sig_shell against Shell identity key and corrected digest.
      const expectedShellAddr = decodeIdentityK1Address(shell.identity_pubkey);
      const digest_shell = shareDigest({
        chain_id: params.chain_id,
        ghost_id: params.ghost_id,
        attempt_id,
        checkpoint_commitment,
        envelope_commitment,
      });
      const recoveredShell = await recoverAddress({ hash: digest_shell, signature: receipt.sig_shell });
      if (recoveredShell.toLowerCase() !== expectedShellAddr.toLowerCase()) throw new Error('InvalidShellReceiptSig');

      // Verify sig_ack only if we have an expected signer address.
      if (member.expected_ack_signer) {
        const digest_ack = shareAckDigest({
          chain_id: params.chain_id,
          ghost_id: params.ghost_id,
          attempt_id,
          checkpoint_commitment,
          envelope_commitment,
        });
        const recoveredAck = await recoverAddress({ hash: digest_ack, signature: receipt.sig_ack });
        if (recoveredAck.toLowerCase() !== member.expected_ack_signer.toLowerCase()) throw new Error('InvalidAckReceiptSig');
      }

      receipts.push(receipt);
      distributionLog.push({
        ghost_id: params.ghost_id,
        epoch: params.epoch.toString(),
        shell_id: member.shell_id,
        share_index: share.index,
        checkpoint_commitment,
        envelope_commitment,
        receipt,
        ptr_checkpoint,
        ptr_envelope,
      });
    }

    // 5) Store receipts locally (stand-in for share_distributions table).
    const distPath = join(params.dataDir, 'share_distributions.json');
    await mkdir(params.dataDir, { recursive: true });
    await writeFile(distPath, JSON.stringify(distributionLog, null, 2));

    // 10) Publish on-chain.
    await this.deps.ghostRegistry.publishCheckpoint(
      params.ghost_id,
      params.epoch,
      checkpoint_commitment,
      envelope_commitment,
      ptrToHex(ptr_checkpoint),
      ptrToHex(ptr_envelope),
    );

    return {
      checkpoint_commitment,
      envelope_commitment,
      ptr_checkpoint,
      ptr_envelope,
      share_receipts: receipts,
    };
  }
}
