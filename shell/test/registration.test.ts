import { describe, expect, it } from 'vitest';

import { deriveShellId, shellRegistrationDigest } from '@gits-protocol/sdk';
import { encodeAbiParameters, keccak256, recoverAddress, toBytes } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { encodeIdentityPubkeyK1, encodeOfferSignerPubkeyK1 } from '../src/registration/register.js';

describe('registration', () => {
  it('derives shell_id as keccak256(abi.encode(TAG, identity_pubkey, salt))', () => {
    const identity = privateKeyToAccount(('0x' + '11'.repeat(32)) as Hex);
    const salt = ('0x' + '22'.repeat(32)) as Hex;
    const identityPubkey = encodeIdentityPubkeyK1(identity.address);

    const shellId = deriveShellId(identityPubkey, salt);

    const TAG = keccak256(toBytes('GITS_SHELL_ID'));
    const expected = keccak256(
      encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes' }, { type: 'bytes32' }],
        [TAG, identityPubkey, salt],
      ),
    );

    expect(shellId).toEqual(expected);
  });

  it('signs shellRegistrationDigest with identity key (recoverable address matches)', async () => {
    const identity = privateKeyToAccount(('0x' + '33'.repeat(32)) as Hex);
    const offerSigner = privateKeyToAccount(('0x' + '44'.repeat(32)) as Hex);

    const identityPubkey = encodeIdentityPubkeyK1(identity.address);
    const offerSignerPubkey = encodeOfferSignerPubkeyK1(offerSigner.address);
    const salt = ('0x' + '55'.repeat(32)) as Hex;
    const shellId = deriveShellId(identityPubkey, salt);

    const digest = shellRegistrationDigest({
      shell_id: shellId,
      payout_address: identity.address,
      offer_signer_pubkey: offerSignerPubkey,
      bond_asset: identity.address,
      bond_amount: 123n,
      salt,
      registry_nonce: 7n,
      chain_id: 31337n,
    });

    const sig = await identity.sign({ hash: digest });
    const recovered = await recoverAddress({ hash: digest, signature: sig });
    expect(recovered.toLowerCase()).toEqual(identity.address.toLowerCase());
  });
});

