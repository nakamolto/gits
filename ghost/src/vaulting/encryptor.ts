import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from 'node:crypto';

export type EncryptedVault = {
  ciphertext: Uint8Array;
  nonce: Uint8Array; // 12 bytes
  tag: Uint8Array; // 16 bytes
};

export function deriveVaultKey(identityPrivateKey: Uint8Array): Uint8Array {
  const salt = utf8ToBytes('GITS_VAULT_KEY');
  const info = new Uint8Array([]);
  return hkdf(sha256, identityPrivateKey, salt, info, 32);
}

export function encrypt(plaintext: Uint8Array, vaultKey: Uint8Array): EncryptedVault {
  if (vaultKey.length !== 32) throw new Error(`InvalidVaultKeyLength:${vaultKey.length}`);
  const nonce = randomBytes(12);

  const aes = gcm(vaultKey, nonce);
  const sealed = aes.encrypt(plaintext); // ciphertext || tag (16 bytes)
  if (sealed.length < 16) throw new Error('CiphertextTooShort');

  const tag = sealed.slice(sealed.length - 16);
  const ciphertext = sealed.slice(0, sealed.length - 16);

  return { ciphertext, nonce, tag };
}

export function decrypt(vault: EncryptedVault, vaultKey: Uint8Array): Uint8Array {
  if (vaultKey.length !== 32) throw new Error(`InvalidVaultKeyLength:${vaultKey.length}`);
  if (vault.nonce.length !== 12) throw new Error(`InvalidNonceLength:${vault.nonce.length}`);
  if (vault.tag.length !== 16) throw new Error(`InvalidTagLength:${vault.tag.length}`);

  const aes = gcm(vaultKey, vault.nonce);
  const sealed = new Uint8Array(vault.ciphertext.length + vault.tag.length);
  sealed.set(vault.ciphertext, 0);
  sealed.set(vault.tag, vault.ciphertext.length);

  return aes.decrypt(sealed);
}

