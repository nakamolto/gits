import { encodeAbiParameters, keccak256, verifyTypedData } from 'viem';
import type { Address, Hex, TypedData } from 'viem';

import type { Offer } from '../types/structs.js';
import { offerDomain } from './domains.js';

export function offerId(args: { shell_id: Hex; nonce: bigint; chain_id: bigint }): Hex {
  const { shell_id, nonce, chain_id } = args;
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'uint64' }, { type: 'uint256' }],
      [shell_id, nonce, chain_id],
    ),
  );
}

const OFFER_TYPES = {
  Offer: [
    { name: 'offer_id', type: 'bytes32' },
    { name: 'shell_id', type: 'bytes32' },
    { name: 'chain_id', type: 'uint256' },
    { name: 'nonce', type: 'uint64' },
    { name: 'price_per_SU', type: 'uint256' },
    { name: 'escrow_asset', type: 'address' },
    { name: 'min_lease', type: 'uint64' },
    { name: 'max_SU', type: 'uint64' },
    { name: 'assurance_tier', type: 'uint8' },
    { name: 'capability_hash', type: 'bytes32' },
    { name: 'policy_tags', type: 'bytes' },
    { name: 'region', type: 'bytes32' },
    { name: 'capacity', type: 'uint32' },
    { name: 'expiry', type: 'uint64' },
  ],
} as const satisfies TypedData;

export function offerTypedData(args: { offer: Offer; shell_registry_address: Address }) {
  const { offer, shell_registry_address } = args;
  return {
    domain: offerDomain({ chain_id: offer.chain_id, shell_registry_address }),
    types: OFFER_TYPES,
    primaryType: 'Offer' as const,
    message: offer,
  };
}

export async function verifyOffer(args: {
  offer: Offer;
  signature: Hex;
  offer_signer_address: Address;
  shell_registry_address: Address;
}): Promise<boolean> {
  const { offer, signature, offer_signer_address, shell_registry_address } = args;
  const td = offerTypedData({ offer, shell_registry_address });

  return verifyTypedData({
    address: offer_signer_address,
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.message,
    signature,
  });
}

