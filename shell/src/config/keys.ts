import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

import { bytesToHex, hexToBytes, isHex } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

export type KeyPurpose = 'identity' | 'offer-signer' | 'recovery';

export interface LoadedKey {
  purpose: KeyPurpose;
  privateKey: Hex; // 0x + 32 bytes
  address: Hex; // 0x + 20 bytes
  publicKeyUncompressed: Hex; // 0x04.. 65 bytes
}

export interface SessionKey {
  privateKey: Hex;
  publicKeyUncompressed: Hex;
}

type EncryptedKeyfileV1 = {
  version: 1;
  kdf: {
    name: 'scrypt';
    salt_b64: string;
    n: number;
    r: number;
    p: number;
    dklen: number;
  };
  cipher: {
    name: 'aes-256-gcm';
    iv_b64: string;
    tag_b64: string;
  };
  ciphertext_b64: string;
};

function expandHome(p: string): string {
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

function assertPrivateKeyHex(v: string): asserts v is Hex {
  if (!isHex(v, { strict: true }) || v.length !== 66) throw new Error('private key must be 32-byte hex (0x + 64 chars)');
}

function scryptKey(passphrase: string, salt: Uint8Array, n: number, r: number, p: number, dkLen: number): Buffer {
  return crypto.scryptSync(passphrase, salt, dkLen, { N: n, r, p }) as Buffer;
}

export function encryptPrivateKey(passphrase: string, privateKey: Hex): EncryptedKeyfileV1 {
  assertPrivateKeyHex(privateKey);

  const salt = crypto.randomBytes(16);
  const n = 1 << 15;
  const r = 8;
  const p = 1;
  const dklen = 32;
  const key = scryptKey(passphrase, salt, n, r, p, dklen);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const plaintext = Buffer.from(hexToBytes(privateKey));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: 1,
    kdf: { name: 'scrypt', salt_b64: salt.toString('base64'), n, r, p, dklen },
    cipher: { name: 'aes-256-gcm', iv_b64: iv.toString('base64'), tag_b64: tag.toString('base64') },
    ciphertext_b64: ciphertext.toString('base64'),
  };
}

export function decryptPrivateKey(passphrase: string, keyfile: EncryptedKeyfileV1): Hex {
  if (keyfile.version !== 1) throw new Error(`unsupported keyfile version: ${String((keyfile as any).version)}`);
  if (keyfile.kdf.name !== 'scrypt') throw new Error('unsupported kdf');
  if (keyfile.cipher.name !== 'aes-256-gcm') throw new Error('unsupported cipher');

  const salt = Buffer.from(keyfile.kdf.salt_b64, 'base64');
  const key = scryptKey(passphrase, salt, keyfile.kdf.n, keyfile.kdf.r, keyfile.kdf.p, keyfile.kdf.dklen);

  const iv = Buffer.from(keyfile.cipher.iv_b64, 'base64');
  const tag = Buffer.from(keyfile.cipher.tag_b64, 'base64');
  const ciphertext = Buffer.from(keyfile.ciphertext_b64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (plaintext.length !== 32) throw new Error('invalid plaintext length');
  return bytesToHex(plaintext) as Hex;
}

export async function writeKeyfile(keyPath: string, keyfile: EncryptedKeyfileV1): Promise<void> {
  const p = expandHome(keyPath);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(keyfile, null, 2) + '\n', { mode: 0o600 });
}

export async function readKeyfile(keyPath: string): Promise<EncryptedKeyfileV1> {
  const p = expandHome(keyPath);
  const raw = await fs.readFile(p, 'utf8');
  return JSON.parse(raw) as EncryptedKeyfileV1;
}

export async function promptPassphrase(label: string): Promise<string> {
  // Minimal prompt (stdin echo is not disabled); v1 ergonomics. Avoid logging the passphrase.
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    const passphrase = await new Promise<string>((resolve) => rl.question(`${label}: `, resolve));
    return passphrase;
  } finally {
    rl.close();
  }
}

export async function loadKeyFromFile(args: { purpose: KeyPurpose; path: string; passphrase: string }): Promise<LoadedKey> {
  const keyfile = await readKeyfile(args.path);
  const privateKey = decryptPrivateKey(args.passphrase, keyfile);
  const account = privateKeyToAccount(privateKey);
  return {
    purpose: args.purpose,
    privateKey,
    address: account.address,
    publicKeyUncompressed: account.publicKey,
  };
}

export function generateSessionKey(): SessionKey {
  while (true) {
    const privBytes = crypto.randomBytes(32);
    const privateKey = bytesToHex(privBytes) as Hex;
    try {
      const account = privateKeyToAccount(privateKey);
      return { privateKey, publicKeyUncompressed: account.publicKey };
    } catch {
      // Extremely unlikely; retry if private key invalid.
    }
  }
}

