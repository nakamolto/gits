import { describe, expect, it, vi } from 'vitest';

import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { encodeAbiParameters, keccak256, toBytes, toHex, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { x25519 } from '@noble/curves/ed25519.js';

import { decrypt, deriveVaultKey, encrypt } from '../src/vaulting/encryptor.js';
import { evalPolyAt, gfInv, gfMul, reconstructVaultKey, splitVaultKey } from '../src/vaulting/shamir.js';
import { CheckpointPublisher, FileStorageBackend, type SafeHavenTransport } from '../src/vaulting/checkpoint-publisher.js';

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

describe('vault encryptor', () => {
  it('deriveVaultKey is deterministic', () => {
    const id = randomBytes(32);
    const k1 = deriveVaultKey(id);
    const k2 = deriveVaultKey(id);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);

    const other = randomBytes(32);
    const k3 = deriveVaultKey(other);
    expect(Buffer.from(k1).equals(Buffer.from(k3))).toBe(false);
  });

  it('encrypt/decrypt roundtrip', () => {
    const key = deriveVaultKey(randomBytes(32));
    for (const n of [0, 1, 32, 1024]) {
      const pt = randomBytes(n);
      const vault = encrypt(pt, key);
      const out = decrypt(vault, key);
      expect(Buffer.from(out).equals(Buffer.from(pt))).toBe(true);
    }
  });
});

describe('GF(2^8) arithmetic', () => {
  it('gfMul matches a known AES field vector', () => {
    // Standard Rijndael example: 0x57 * 0x83 = 0xC1 in GF(256) with poly 0x11B.
    expect(gfMul(0x57, 0x83)).toBe(0xc1);
  });

  it('gfInv produces a multiplicative inverse', () => {
    for (let i = 1; i <= 50; i++) {
      const a = i * 3; // deterministic, non-zero
      const inv = gfInv(a);
      expect(gfMul(a, inv)).toBe(1);
    }
  });

  it('evalPolyAt matches explicit evaluation', () => {
    const coeffs = new Uint8Array([0x01, 0x02, 0x03]); // 1 + 2x + 3x^2
    const x = 0x05;
    const expected = 0x01 ^ gfMul(0x02, x) ^ gfMul(0x03, gfMul(x, x));
    expect(evalPolyAt(coeffs, x)).toBe(expected & 0xff);
  });
});

describe('Shamir split/reconstruct', () => {
  it('3-of-5 reconstructs with any 3; 2 shares fails', () => {
    const key = randomBytes(32);
    const shares = splitVaultKey(key, 3, 5);

    const combos = [
      [0, 1, 2],
      [0, 1, 3],
      [0, 2, 4],
      [1, 3, 4],
      [2, 3, 4],
    ];
    for (const c of combos) {
      const rec = reconstructVaultKey([shares[c[0]], shares[c[1]], shares[c[2]]], 3);
      expect(Buffer.from(rec).equals(Buffer.from(key))).toBe(true);
    }

    expect(() => reconstructVaultKey([shares[0], shares[1]], 3)).toThrow(/InsufficientShares/);
  });

  it('threshold=1 is trivial', () => {
    const key = randomBytes(32);
    const shares = splitVaultKey(key, 1, 5);
    for (const s of shares) {
      const rec = reconstructVaultKey([s], 1);
      expect(Buffer.from(rec).equals(Buffer.from(key))).toBe(true);
    }
  });

  it('threshold=n requires all n', () => {
    const key = randomBytes(32);
    const shares = splitVaultKey(key, 5, 5);
    const rec = reconstructVaultKey(shares, 5);
    expect(Buffer.from(rec).equals(Buffer.from(key))).toBe(true);
    expect(() => reconstructVaultKey(shares.slice(0, 4), 5)).toThrow(/InsufficientShares/);
  });
});

describe('CheckpointPublisher', () => {
  it('publishes commitments, stores blobs, distributes shares, and verifies receipts', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'gits-ghost-'));
    const agentDataDir = join(tmp, 'agent');
    const dataDir = join(tmp, 'data');
    await mkdir(agentDataDir, { recursive: true });
    await writeFile(join(agentDataDir, 'state.json'), JSON.stringify({ hello: 'world' }));

    const chain_id = 8453n;
    const ghost_id = ('0x' + '11'.repeat(32)) as Hex;
    const epoch = 42n;
    const attempt_id = epoch;
    const vaultKey = deriveVaultKey(randomBytes(32));

    // Safe Havens: identity keys (K1 addresses) and x25519 recovery pubkeys.
    const shellAccounts = Array.from({ length: 5 }, (_, i) =>
      privateKeyToAccount((('0x' + (i + 1).toString(16).padStart(64, '0')) as Hex)),
    );
    const ackAccount = privateKeyToAccount(('0x' + 'ab'.repeat(32)) as Hex);

    const recoveryKeys = shellAccounts.map(() => {
      const sk = x25519.utils.randomSecretKey();
      const pk = x25519.getPublicKey(sk);
      return { sk, pk };
    });

    const shells = new Map<Hex, { identity_pubkey: Hex; recovery_pubkey: Hex; addr: Address }>();
    const recoverySet = shellAccounts.map((acct, i) => {
      const shell_id = keccak256(toBytes(`shell-${i}`)) as Hex;
      shells.set(shell_id, {
        identity_pubkey: k1IdentityPubkey(acct.address),
        recovery_pubkey: toHex(recoveryKeys[i].pk),
        addr: acct.address,
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

    const publishCheckpoint = vi.fn(async () => undefined);
    const ghostRegistry = { publishCheckpoint };

    const transportCalls: Array<{ shell_id: Hex; payload: Uint8Array }> = [];
    const transport: SafeHavenTransport = {
      async sendShare(args) {
        transportCalls.push({ shell_id: args.shell_id, payload: args.payload });

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

        const shellAccount = shellAccounts[recoverySet.findIndex((m) => m.shell_id === args.shell_id)];
        const sig_shell = await shellAccount.sign({ hash: d1 });
        const sig_ack = await ackAccount.sign({ hash: d2 });

        return { receipt: { shell_id: args.shell_id, sig_shell, sig_ack } };
      },
    };

    const publisher = new CheckpointPublisher({
      shellRegistry,
      ghostRegistry,
      storage: new FileStorageBackend(),
      transport,
    });

    const res = await publisher.publish({
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

    expect(res.share_receipts).toHaveLength(5);
    expect(transportCalls).toHaveLength(5);

    // Verify commitments match stored blobs.
    const storedVault = new Uint8Array(await readFile(res.ptr_checkpoint));
    const storedEnv = new Uint8Array(await readFile(res.ptr_envelope));
    expect(keccak256(storedVault)).toBe(res.checkpoint_commitment);
    expect(keccak256(storedEnv)).toBe(res.envelope_commitment);

    // GhostRegistry.publishCheckpoint is called with expected pointers (encoded as bytes).
    expect(publishCheckpoint).toHaveBeenCalledTimes(1);
    const call = publishCheckpoint.mock.calls[0];
    expect(call[0]).toBe(ghost_id);
    expect(call[1]).toBe(epoch);
    expect(call[2]).toBe(res.checkpoint_commitment);
    expect(call[3]).toBe(res.envelope_commitment);
    // ptr_checkpoint and ptr_envelope are bytes; we just sanity-check they are non-empty.
    expect(typeof call[4]).toBe('string');
    expect(typeof call[5]).toBe('string');
    expect((call[4] as string).startsWith('0x')).toBe(true);
    expect((call[5] as string).startsWith('0x')).toBe(true);
  });
});
