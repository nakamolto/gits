import { bytesToHex, getAddress, hexToBytes, keccak256, verifyTypedData } from 'viem';
import type { Address, Hex, TypedData } from 'viem';

import { scoreOffer } from './planner.js';
import type {
  DiscoveredOffer,
  MigrationContext,
  OfferFilters,
  RankedDestination,
  ReputationStore,
  ShellRegistryLike,
  ShellRecord,
} from './types.js';

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

function chainIdNumber(chain_id: bigint): number {
  const n = Number(chain_id);
  if (!Number.isSafeInteger(n) || BigInt(n) !== chain_id) {
    throw new Error('EIP-712 domain: chain_id must fit in a JS safe integer');
  }
  return n;
}

function offerDomain(args: { chain_id: bigint; shell_registry_address: Address }) {
  const { chain_id, shell_registry_address } = args;
  return {
    name: 'GITSOffer',
    version: '1',
    chainId: chainIdNumber(chain_id),
    verifyingContract: shell_registry_address,
  } as const;
}

function offerSignerAddressFromShellRecord(shell: ShellRecord): Address {
  const pk = shell.offer_signer_pubkey;

  // Test-friendly: allow storing the signer address directly.
  if (typeof pk === 'string' && pk.length === 42) return getAddress(pk as Address);

  // Otherwise treat it as an uncompressed public key (0x04 + 64 bytes).
  const bytes = hexToBytes(pk);
  const pubkey = bytes.length === 65 && bytes[0] === 4 ? bytes.subarray(1) : bytes;
  if (pubkey.length !== 64) throw new Error('offer signer pubkey must be 64 or 65 bytes');

  const digest = keccak256(bytesToHex(pubkey));
  return getAddress(('0x' + digest.slice(-40)) as Address);
}

export interface OfferDiscoveryDeps {
  clawEndpoint?: string;
  directOffers?: DiscoveredOffer[];
  fetchFn?: typeof fetch;

  shellRegistry: ShellRegistryLike;
  shellRegistryAddress: Address;
  reputationStore: ReputationStore;
}

export function makeOfferDiscovery(deps: OfferDiscoveryDeps) {
  return {
    queryOffers: (filters: OfferFilters) => queryOffers(filters, deps),
    rankOffers: (offers: DiscoveredOffer[], ctx: MigrationContext) => rankOffers(offers, ctx, deps),
  };
}

export async function queryOffers(filters: OfferFilters, deps: Pick<OfferDiscoveryDeps, 'clawEndpoint' | 'directOffers' | 'fetchFn'>) {
  const direct = deps.directOffers ?? [];
  const out: DiscoveredOffer[] = [];

  for (const o of direct) out.push(o);

  if (deps.clawEndpoint) {
    const url = new URL(deps.clawEndpoint);
    url.searchParams.set('asset', filters.asset);
    url.searchParams.set('min_at', String(filters.minAssuranceTier));
    url.searchParams.set('max_price', filters.maxPricePerSU.toString());
    url.searchParams.set('min_su', filters.minMaxSU.toString());

    const fetchFn = deps.fetchFn ?? fetch;
    const res = await fetchFn(url.toString(), { method: 'GET' });
    if (!res.ok) throw new Error(`ClawBNB query failed: ${res.status} ${res.statusText}`);

    const data = (await res.json()) as unknown;
    if (!data || typeof data !== 'object' || !Array.isArray((data as any).offers)) {
      throw new Error('ClawBNB response malformed: expected { offers: [...] }');
    }
    for (const item of (data as any).offers as any[]) {
      if (!item || typeof item !== 'object') continue;
      if (!item.offer || !item.signature || !item.endpoint) continue;
      out.push(item as DiscoveredOffer);
    }
  }

  // Filter/dedupe.
  const seen = new Set<string>();
  return out.filter((d) => {
    const id = d.offer.offer_id;
    if (filters.excludeShellIds.includes(d.offer.shell_id)) return false;
    if (d.offer.escrow_asset !== filters.asset) return false;
    if (d.offer.assurance_tier < filters.minAssuranceTier) return false;
    if (d.offer.price_per_SU > filters.maxPricePerSU) return false;
    if (d.offer.max_SU < filters.minMaxSU) return false;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

export async function verifyOffer(
  discovered: DiscoveredOffer,
  deps: Pick<OfferDiscoveryDeps, 'shellRegistry' | 'shellRegistryAddress'>,
): Promise<boolean> {
  try {
    const shell = await deps.shellRegistry.getShell(discovered.offer.shell_id);
    const offer_signer_address = offerSignerAddressFromShellRecord(shell);
    const td = {
      domain: offerDomain({
        chain_id: discovered.offer.chain_id,
        shell_registry_address: deps.shellRegistryAddress,
      }),
      types: OFFER_TYPES,
      primaryType: 'Offer' as const,
      message: discovered.offer,
    };

    return verifyTypedData({
      address: offer_signer_address,
      domain: td.domain,
      types: td.types,
      primaryType: td.primaryType,
      message: td.message,
      signature: discovered.signature,
    });
  } catch {
    return false;
  }
}

export async function verifyShellOnChain(
  shellId: Hex,
  deps: { shellRegistry: ShellRegistryLike; minAssuranceTier: number },
): Promise<boolean> {
  const shell = await deps.shellRegistry.getShell(shellId);
  if (shell.bond_status !== 0) return false;

  const at = await deps.shellRegistry.assuranceTier(shellId);
  return at >= deps.minAssuranceTier;
}

export async function rankOffers(
  offers: DiscoveredOffer[],
  ctx: MigrationContext,
  deps: Pick<OfferDiscoveryDeps, 'shellRegistry' | 'shellRegistryAddress' | 'reputationStore'>,
): Promise<RankedDestination[]> {
  const ranked: RankedDestination[] = [];

  for (const discovered of offers) {
    if (ctx.preferences.blacklistShellIds.includes(discovered.offer.shell_id)) continue;

    const shellOk = await verifyShellOnChain(discovered.offer.shell_id, {
      shellRegistry: deps.shellRegistry,
      minAssuranceTier: ctx.preferences.minAssuranceTier,
    });
    if (!shellOk) continue;

    const sigOk = await verifyOffer(discovered, {
      shellRegistry: deps.shellRegistry,
      shellRegistryAddress: deps.shellRegistryAddress,
    });
    if (!sigOk) continue;

    let rep = 0;
    try {
      rep = await deps.reputationStore.getShellReputation(discovered.offer.shell_id);
    } catch {
      rep = 0;
    }

    const score = scoreOffer({ discovered, context: ctx, reputation: rep });
    if (!Number.isFinite(score)) continue;

    ranked.push({ discovered, score });
  }

  ranked.sort((a, b) => b.score - a.score);
  return ranked;
}
