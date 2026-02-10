import crypto from 'node:crypto';

import { deriveShellId, shellRegistrationDigest } from '@gits-protocol/sdk';
import { encodeAbiParameters, hexToBytes, isHex, toHex } from 'viem';
import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { ShellConfig } from '../config/config.js';
import type { LoadedKey } from '../config/keys.js';
import type { ShellDb } from '../storage/db.js';
import type { ChainSubmitter } from '../chain/submitter.js';

export interface RegisterResult {
  shellId: Hex;
  salt: Hex;
  txHash: Hex;
}

export function encodeIdentityPubkeyK1(identityAddress: Address): Hex {
  const pkBytes = encodeAbiParameters([{ type: 'address' }], [identityAddress]);
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1, pkBytes]);
}

export function encodeOfferSignerPubkeyK1(offerSignerAddress: Address): Hex {
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'address' }], [1, offerSignerAddress]);
}

export async function registerShell(args: {
  cfg: ShellConfig;
  db: ShellDb;
  chain: ChainSubmitter;
  identityKey: LoadedKey;
  offerSignerKey: LoadedKey;
  salt?: Hex;
  cert?: Hex;
  sigsCert?: Hex[];
}): Promise<RegisterResult> {
  const identityAccount = privateKeyToAccount(args.identityKey.privateKey);
  const offerSignerAccount = privateKeyToAccount(args.offerSignerKey.privateKey);

  const salt = args.salt ?? (toHex(crypto.randomBytes(32)) as Hex);
  const identityPubkey = encodeIdentityPubkeyK1(identityAccount.address);
  const offerSignerPubkey = encodeOfferSignerPubkeyK1(offerSignerAccount.address);

  const shellId = deriveShellId(identityPubkey, salt);
  const registryNonce = await args.chain.readRegistryNonce();

  const digest = shellRegistrationDigest({
    shell_id: shellId,
    payout_address: args.cfg.identity.payoutAddress,
    offer_signer_pubkey: offerSignerPubkey,
    bond_asset: args.cfg.bond.bondAsset,
    bond_amount: args.cfg.bond.bondAmount,
    salt,
    registry_nonce: registryNonce,
    chain_id: args.cfg.chain.chainId,
  });

  const sig = (await identityAccount.sign({ hash: digest })) as Hex;

  // Approve bond asset transfer.
  await args.chain.approveErc20({
    asset: args.cfg.bond.bondAsset,
    spender: args.cfg.chain.deployment.shellRegistry,
    amount: args.cfg.bond.bondAmount,
  });

  const txHash = await args.chain.registerShell({
    shellId,
    identityPubkey,
    offerSignerPubkey,
    payoutAddress: args.cfg.identity.payoutAddress,
    salt,
    bondAsset: args.cfg.bond.bondAsset,
    bondAmount: args.cfg.bond.bondAmount,
    cert: args.cert ?? '0x',
    sigsCert: args.sigsCert ?? [],
    sig,
  });

  args.db.setMeta('shell_id', shellId);

  return { shellId, salt, txHash };
}

