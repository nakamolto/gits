import { describe, expect, it } from 'vitest';

import { randomBytes } from 'node:crypto';

import { decrypt, decodeVaultBlob, encodeVaultBlob, encrypt } from '../src/vaulting/encryptor.js';

describe('vault blob codec', () => {
  it('encrypt+encode decrypt+decode roundtrip', () => {
    const key = randomBytes(32);
    const plaintext = randomBytes(128);

    const vault = encrypt(plaintext, key);
    const blob = encodeVaultBlob(vault);

    const decoded = decodeVaultBlob(blob);
    const out = decrypt(decoded, key);

    expect(Buffer.from(out)).toEqual(plaintext);
  });

  it('throws on invalid version', () => {
    const blob = new Uint8Array(29);
    blob[0] = 2;
    expect(() => decodeVaultBlob(blob)).toThrow('UnsupportedVaultVersion:2');
  });

  it('throws on truncated blob', () => {
    expect(() => decodeVaultBlob(new Uint8Array([1]))).toThrow('VaultBlobTooShort');
  });
});
