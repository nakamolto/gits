import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

export type SecureStoreKdfParams = {
  n: number;
  r: number;
  p: number;
  dkLen: number;
};

export type SecureStoreHeaderV1 = {
  v: 1;
  kdf: 'scrypt';
  kdfParams: SecureStoreKdfParams;
  saltB64: string;
  nonceB64: string;
  tagB64: string;
};

const DEFAULT_KDF_PARAMS: SecureStoreKdfParams = {
  // Roughly aligned with common interactive defaults; adjust later if needed.
  n: 1 << 15,
  r: 8,
  p: 1,
  dkLen: 32,
};

function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromB64(s: string): Uint8Array {
  return Buffer.from(s, 'base64');
}

function splitHeaderAndCiphertext(blob: Uint8Array): { header: SecureStoreHeaderV1; ciphertext: Uint8Array } {
  const nl = Buffer.from(blob).indexOf('\n');
  if (nl === -1) throw new Error('SecureStore: invalid blob (missing header delimiter)');

  const headerJson = Buffer.from(blob.slice(0, nl)).toString('utf8');
  let headerUnknown: unknown;
  try {
    headerUnknown = JSON.parse(headerJson);
  } catch {
    throw new Error('SecureStore: invalid header JSON');
  }

  if (
    !headerUnknown ||
    typeof headerUnknown !== 'object' ||
    (headerUnknown as any).v !== 1 ||
    (headerUnknown as any).kdf !== 'scrypt'
  ) {
    throw new Error('SecureStore: unsupported header');
  }

  const header = headerUnknown as SecureStoreHeaderV1;
  if (
    typeof header.saltB64 !== 'string' ||
    typeof header.nonceB64 !== 'string' ||
    typeof header.tagB64 !== 'string' ||
    !header.kdfParams ||
    typeof header.kdfParams.n !== 'number' ||
    typeof header.kdfParams.r !== 'number' ||
    typeof header.kdfParams.p !== 'number' ||
    typeof header.kdfParams.dkLen !== 'number'
  ) {
    throw new Error('SecureStore: invalid header fields');
  }

  const ciphertext = blob.slice(nl + 1);
  return { header, ciphertext };
}

async function deriveKey(passphrase: string, salt: Uint8Array, params: SecureStoreKdfParams): Promise<Uint8Array> {
  if (!passphrase) throw new Error('SecureStore: empty passphrase');

  const key = await new Promise<Buffer>((resolve, reject) => {
    scryptCb(
      passphrase,
      Buffer.from(salt),
      params.dkLen,
      {
        N: params.n,
        r: params.r,
        p: params.p,
        maxmem: 128 * 1024 * 1024,
      },
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve(derivedKey as Buffer);
      },
    );
  });
  return new Uint8Array(key);
}

export async function encryptToBytes(
  plaintext: Uint8Array,
  passphrase: string,
  opts?: { kdfParams?: Partial<SecureStoreKdfParams>; saltBytes?: number; nonceBytes?: number },
): Promise<Uint8Array> {
  const kdfParams: SecureStoreKdfParams = {
    ...DEFAULT_KDF_PARAMS,
    ...(opts?.kdfParams ?? {}),
  };

  const salt = randomBytes(opts?.saltBytes ?? 16);
  const nonce = randomBytes(opts?.nonceBytes ?? 12);
  const key = await deriveKey(passphrase, salt, kdfParams);

  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();

  const header: SecureStoreHeaderV1 = {
    v: 1,
    kdf: 'scrypt',
    kdfParams,
    saltB64: toB64(salt),
    nonceB64: toB64(nonce),
    tagB64: toB64(tag),
  };

  const headerLine = Buffer.from(JSON.stringify(header), 'utf8');
  return new Uint8Array(Buffer.concat([headerLine, Buffer.from('\n'), ciphertext]));
}

export async function decryptFromBytes(blob: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const { header, ciphertext } = splitHeaderAndCiphertext(blob);

  const salt = fromB64(header.saltB64);
  const nonce = fromB64(header.nonceB64);
  const tag = fromB64(header.tagB64);

  const key = await deriveKey(passphrase, salt, header.kdfParams);

  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  decipher.setAuthTag(Buffer.from(tag));

  const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  return new Uint8Array(plaintext);
}

export async function encryptToFile(
  filePath: string,
  plaintext: Uint8Array,
  passphrase: string,
  opts?: { kdfParams?: Partial<SecureStoreKdfParams>; saltBytes?: number; nonceBytes?: number },
): Promise<void> {
  const blob = await encryptToBytes(plaintext, passphrase, opts);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, blob);
}

export async function decryptFromFile(filePath: string, passphrase: string): Promise<Uint8Array> {
  const blob = await fs.readFile(filePath);
  return decryptFromBytes(new Uint8Array(blob), passphrase);
}
