import { encodeAbiParameters, bytesToHex, hexToBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from 'viem';
import type { LocalAccount } from 'viem/accounts';
import * as secp from '@noble/secp256k1';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { decryptFromFile } from '../storage/secure-store.js';

// `LocalAccount`'s `sign` is optional at the type level, but Ghost always needs hash signing.
export type LocalSignerAccount = LocalAccount & { sign: NonNullable<LocalAccount['sign']> };

export type IdentityKey = {
  privKey: Uint8Array;
  privKeyHex: Hex;
  account: LocalSignerAccount;
  // Canonical on-chain encoding: abi.encode(uint8(1), abi.encode(address))
  identityPubkeyBytes: Hex;
};

export type SessionKey = {
  privKey: Uint8Array;
  pubKeyUncompressed: Uint8Array;
  // Canonical on-chain encoding: abi.encode(uint8(1), pubkey_uncompressed_65)
  sessionKeyBytes: Hex;
  account: LocalSignerAccount;
};

export async function loadIdentityKey(identityKeyPath: string, passphrase: string): Promise<IdentityKey> {
  const plaintext = await decryptFromFile(identityKeyPath, passphrase);

  let privKey: Uint8Array;
  if (plaintext.length === 32) {
    privKey = plaintext;
  } else {
    // Future-proof: allow JSON wrapper with `privateKeyHex`.
    let parsed: any;
    try {
      parsed = JSON.parse(Buffer.from(plaintext).toString('utf8'));
    } catch {
      throw new Error('IdentityKey: invalid key file (expected 32-byte private key or JSON wrapper)');
    }
    if (!parsed || typeof parsed.privateKeyHex !== 'string') {
      throw new Error('IdentityKey: invalid JSON wrapper (missing privateKeyHex)');
    }
    privKey = hexToBytes(parsed.privateKeyHex as Hex);
    if (privKey.length !== 32) throw new Error('IdentityKey: invalid privateKeyHex length');
  }

  const privKeyHex = bytesToHex(privKey);
  const account = privateKeyToAccount(privKeyHex);

  const pkBytes = encodeAbiParameters([{ type: 'address' }], [account.address]);
  const identityPubkeyBytes = encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pkBytes]);

  return {
    privKey,
    privKeyHex,
    account: account as LocalSignerAccount,
    identityPubkeyBytes,
  };
}

export function generateSessionKey(): SessionKey {
  const privKey = secp.utils.randomSecretKey();
  const pubKeyUncompressed = secp.getPublicKey(privKey, false);
  const sessionKeyBytes = encodeAbiParameters(
    [{ type: 'uint8' }, { type: 'bytes' }],
    [1, bytesToHex(pubKeyUncompressed)],
  );

  // viem LocalAccount signing expects a 32-byte private key; reuse the generated session key.
  const account = privateKeyToAccount(bytesToHex(privKey));

  return {
    privKey,
    pubKeyUncompressed,
    sessionKeyBytes,
    account: account as LocalSignerAccount,
  };
}

export function deriveVaultKey(identityPrivKey: Uint8Array): Uint8Array {
  if (identityPrivKey.length !== 32) throw new Error('VaultKey: identity private key must be 32 bytes');

  // Deterministic vault key: HKDF-SHA256(PRK=identityPrivKey, info="GITS_VAULT_KEY")
  const info = new TextEncoder().encode('GITS_VAULT_KEY');
  const okm = hkdf(sha256, identityPrivKey, undefined, info, 32);
  return new Uint8Array(okm);
}
