import { describe, expect, it } from 'vitest';

import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomBytes } from 'node:crypto';

import { encodeAbiParameters, bytesToHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { loadGhostConfig } from '../src/config/config.js';
import { decryptFromBytes, encryptToBytes } from '../src/storage/secure-store.js';
import { deriveVaultKey, generateSessionKey, loadIdentityKey } from '../src/config/keys.js';

function hex32(byte: string): string {
  return '0x' + byte.repeat(32);
}

describe('Config loading', () => {
  it('parses a valid TOML config and applies defaults', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-config-'));
    const p = path.join(dir, 'ghost.toml');

    const toml = `
# required
ghostId = "${hex32('11')}"
walletAddress = "0x1111111111111111111111111111111111111111"
rpcUrl = "https://example.invalid"

dataDir = "${dir}"

[deployment]
chain_id = 8453

git_token = "0x0000000000000000000000000000000000000001"
shell_registry = "0x0000000000000000000000000000000000000002"
ghost_registry = "0x0000000000000000000000000000000000000003"
session_manager = "0x0000000000000000000000000000000000000004"
receipt_manager = "0x0000000000000000000000000000000000000005"
rewards_manager = "0x0000000000000000000000000000000000000006"
verifier_registry = "0x0000000000000000000000000000000000000007"
`;

    await fs.writeFile(p, toml, 'utf8');

    const cfg = await loadGhostConfig(p);

    expect(cfg.ghostId).toBe(hex32('11'));
    expect(cfg.walletAddress).toBe('0x1111111111111111111111111111111111111111');

    // Defaults.
    expect(cfg.identityKeyPath).toBe(path.join(dir, 'identity.key'));
    expect(cfg.chainId).toBe(8453n);
    expect(cfg.telemetry.logLevel).toBe('info');
    expect(cfg.migration.enabled).toBe(false);
    expect(cfg.vaulting.enabled).toBe(false);
  });

  it('throws on missing required fields', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-config-missing-'));
    const p = path.join(dir, 'ghost.toml');

    const toml = `
walletAddress = "0x1111111111111111111111111111111111111111"
rpcUrl = "https://example.invalid"

[deployment]
chain_id = 1

git_token = "0x0000000000000000000000000000000000000001"
shell_registry = "0x0000000000000000000000000000000000000002"
ghost_registry = "0x0000000000000000000000000000000000000003"
session_manager = "0x0000000000000000000000000000000000000004"
receipt_manager = "0x0000000000000000000000000000000000000005"
rewards_manager = "0x0000000000000000000000000000000000000006"
verifier_registry = "0x0000000000000000000000000000000000000007"
`;

    await fs.writeFile(p, toml, 'utf8');

    await expect(loadGhostConfig(p)).rejects.toThrow(/ghostId/i);
  });
});

describe('Key management', () => {
  it('secure-store encrypt/decrypt roundtrip', async () => {
    const pass = 'correct horse battery staple';
    const plain = randomBytes(32);

    const blob = await encryptToBytes(plain, pass);
    const out = await decryptFromBytes(blob, pass);

    expect(Buffer.from(out)).toEqual(Buffer.from(plain));
  });

  it('identity key encrypt/decrypt roundtrip via loadIdentityKey', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gits-ghost-keys-'));
    const p = path.join(dir, 'identity.key');

    const pass = 'hunter2';
    const privKey = randomBytes(32);

    const blob = await encryptToBytes(privKey, pass);
    await fs.writeFile(p, blob);

    const id = await loadIdentityKey(p, pass);
    expect(Buffer.from(id.privKey)).toEqual(Buffer.from(privKey));

    const expected = privateKeyToAccount(bytesToHex(privKey));
    expect(id.account.address).toBe(expected.address);

    const pkBytes = encodeAbiParameters([{ type: 'address' }], [expected.address]);
    const expectedEncoding = encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pkBytes]);
    expect(id.identityPubkeyBytes).toBe(expectedEncoding);
  });

  it('session key generation + deterministic vault key derivation', () => {
    const s = generateSessionKey();
    expect(s.privKey.length).toBe(32);
    expect(s.pubKeyUncompressed.length).toBe(65);
    expect(s.pubKeyUncompressed[0]).toBe(0x04);
    expect(s.sessionKeyBytes.startsWith('0x')).toBe(true);

    const seed = new Uint8Array(32).fill(7);
    const a = deriveVaultKey(seed);
    const b = deriveVaultKey(seed);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });
});
