import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';

import { keccak256, toHex } from 'viem';

import { encrypt, decrypt } from '../vaulting/encryptor.js';
import { encodeVaultBlob, decodeVaultBlob } from '../vaulting/encryptor.js';

import type { MigrationBundle, PackagerOpts } from './types.js';

export class BundleHashMismatchError extends Error {
  constructor(message = 'bundle hash mismatch') {
    super(message);
    this.name = 'BundleHashMismatchError';
  }
}

export class InvalidBundleError extends Error {
  constructor(message = 'invalid migration bundle') {
    super(message);
    this.name = 'InvalidBundleError';
  }
}

type ManifestV1 = {
  version: 1;
  files: Array<{ path: string; data_b64: string }>;
};

async function walkFiles(root: string): Promise<string[]> {
  const out: string[] = [];

  async function visit(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const ent of entries) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        await visit(p);
        continue;
      }
      if (ent.isFile()) {
        out.push(p);
      }
    }
  }

  await visit(root);
  return out;
}

function toRelPosix(root: string, filePath: string): string {
  const rel = path.relative(root, filePath);
  return rel.split(path.sep).join('/');
}

function normalizeRelPosix(rel: string): string {
  const p = rel.replaceAll('\\', '/');
  return path.posix.normalize(p);
}

function ensureSafeRelPath(rel: string): string {
  const norm = normalizeRelPosix(rel);
  if (!norm || norm === '.' || norm.includes('\0')) throw new InvalidBundleError('invalid file path in bundle');
  if (path.posix.isAbsolute(norm)) throw new InvalidBundleError('absolute paths not allowed in bundle');
  if (norm.startsWith('..') || norm.includes('/..')) throw new InvalidBundleError('path traversal not allowed in bundle');
  return norm;
}

export async function estimateBytes(agentDataDir: string): Promise<bigint> {
  const files = await walkFiles(agentDataDir);
  let total = 0n;
  for (const f of files) {
    const st = await fs.stat(f);
    total += BigInt(st.size);
  }
  return total;
}

export async function packageState(agentDataDir: string, opts: PackagerOpts): Promise<MigrationBundle> {
  const compression = opts.compression ?? 'none';
  if (opts.hooks) await opts.hooks.flush();

  const files = await walkFiles(agentDataDir);
  const manifest: ManifestV1 = { version: 1, files: [] };

  for (const filePath of files) {
    const rel = toRelPosix(agentDataDir, filePath);
    const bytes = await fs.readFile(filePath);
    manifest.files.push({ path: rel, data_b64: Buffer.from(bytes).toString('base64') });
  }

  const json = Buffer.from(JSON.stringify(manifest), 'utf8');
  const payload = compression === 'gzip' ? zlib.gzipSync(json) : json;
  const vault = encrypt(new Uint8Array(payload), opts.key);
  const encryptedState = encodeVaultBlob(vault);
  const bundleHash = keccak256(toHex(encryptedState));

  return {
    encryptedState,
    bundleHash,
    metadata: {
      compression,
      format: 'json-files-v1',
      fileCount: manifest.files.length,
      plaintextBytes: json.length,
      compressedBytes: payload.length,
    },
  };
}

export async function restoreState(bundle: MigrationBundle, agentDataDir: string, opts: PackagerOpts): Promise<void> {
  const computed = keccak256(toHex(bundle.encryptedState));
  if (computed !== bundle.bundleHash) throw new BundleHashMismatchError();

  const vault = decodeVaultBlob(bundle.encryptedState);
  const plaintext = decrypt(vault, opts.key);
  const payload =
    bundle.metadata.compression === 'gzip' ? zlib.gunzipSync(Buffer.from(plaintext)) : Buffer.from(plaintext);

  let parsed: unknown;
  try {
    parsed = JSON.parse(payload.toString('utf8'));
  } catch {
    throw new InvalidBundleError('bundle manifest is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object' || (parsed as any).version !== 1 || !Array.isArray((parsed as any).files)) {
    throw new InvalidBundleError('bundle manifest shape invalid');
  }

  const manifest = parsed as ManifestV1;

  for (const entry of manifest.files) {
    const rel = ensureSafeRelPath(entry.path);
    const outPath = path.join(agentDataDir, rel);
    await fs.mkdir(path.dirname(outPath), { recursive: true });
    const bytes = Buffer.from(entry.data_b64, 'base64');
    await fs.writeFile(outPath, bytes);
  }

  if (opts.hooks) await opts.hooks.reload();
}

// Spec-aligned names.
export const packageAgentState = packageState;
export const restoreAgentState = restoreState;

// Exact function names from the prompt.
export { packageState as package, restoreState as restore };
