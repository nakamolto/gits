import { offerId, offerTypedData } from '@gits-protocol/sdk';
import type { Offer } from '@gits-protocol/sdk';
import { bytesToHex, hexToBytes, padHex, zeroAddress, zeroHash } from 'viem';
import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import type { ShellConfig } from '../config/config.js';
import type { LoadedKey } from '../config/keys.js';
import type { ShellDb } from '../storage/db.js';
import { computeDynamicPrice, type PricingState } from './pricing.js';

export interface OfferBundle {
  offer: Offer;
  signature: Hex;
  offerSignerAddress: Address;
  publishedAtMs: number;
}

function bytes32Zero(): Hex {
  return zeroHash;
}

function regionDefault(): Hex {
  return padHex('0x', { size: 32 });
}

export class OfferManager {
  private readonly cfg: ShellConfig;
  private readonly db: ShellDb;
  private readonly offerSigner: LoadedKey;
  private readonly nowEpoch: () => Promise<bigint>;
  private readonly readAssuranceTier: () => Promise<number>;

  private bundle: OfferBundle | undefined;
  private pricing: PricingState;
  private activeSessions = 0;

  constructor(args: {
    cfg: ShellConfig;
    db: ShellDb;
    offerSigner: LoadedKey;
    nowEpoch: () => Promise<bigint>;
    readAssuranceTier: () => Promise<number>;
  }) {
    this.cfg = args.cfg;
    this.db = args.db;
    this.offerSigner = args.offerSigner;
    this.nowEpoch = args.nowEpoch;
    this.readAssuranceTier = args.readAssuranceTier;
    this.pricing = { pricePerSU: args.cfg.offers.basePricePerSU, lastPublishedAtMs: 0 };
  }

  getActiveSessions(): number {
    return this.activeSessions;
  }

  setActiveSessions(n: number): void {
    this.activeSessions = n;
  }

  getOfferBundle(): OfferBundle | undefined {
    return this.bundle;
  }

  private getAndBumpNonce(): bigint {
    const cur = this.db.getMeta('offer_nonce');
    const nonce = cur ? BigInt(cur) : 0n;
    this.db.setMeta('offer_nonce', (nonce + 1n).toString());
    return nonce;
  }

  async maybeRepublishDynamic(nowMs: number): Promise<OfferBundle | undefined> {
    const nextPricing = computeDynamicPrice({
      cfg: {
        basePricePerSU: this.cfg.offers.basePricePerSU,
        enabled: this.cfg.offers.dynamicPricing,
        premiumMultiplierBps: this.cfg.offers.premiumMultiplierBps,
        maxConcurrentSessions: this.cfg.compute.maxConcurrentSessions,
        minUpdateIntervalMs: 30_000,
      },
      activeSessions: this.activeSessions,
      prev: this.pricing,
      nowMs,
    });

    if (nextPricing === this.pricing) return undefined;
    this.pricing = nextPricing;
    await this.publish({ pricePerSU: nextPricing.pricePerSU });
    return this.bundle;
  }

  async publish(args?: { pricePerSU?: bigint; forceNonce?: bigint }): Promise<OfferBundle> {
    const chainId = this.cfg.chain.chainId;
    const shellId = this.cfg.identity.shellId ?? (this.db.getMeta('shell_id') as Hex | undefined);
    if (!shellId) throw new Error('cannot publish offer: shell_id not set (run register or set identity.shellId)');

    const nowEpoch = await this.nowEpoch();
    const nonce = args?.forceNonce ?? this.getAndBumpNonce();
    const pricePerSU = args?.pricePerSU ?? this.pricing.pricePerSU;

    const offer_id = offerId({ shell_id: shellId, nonce, chain_id: chainId });
    const assurance_tier = await this.readAssuranceTier().catch(() => 0);

    const offer: Offer = {
      offer_id,
      shell_id: shellId,
      chain_id: chainId,
      nonce,
      price_per_SU: pricePerSU,
      escrow_asset: this.cfg.offers.asset,
      min_lease: this.cfg.offers.minLeaseEpochs,
      max_SU: BigInt(this.cfg.compute.maxSUPerEpoch),
      assurance_tier,
      capability_hash: this.cfg.tee?.measurementHash ?? bytes32Zero(),
      policy_tags: '0x',
      region: regionDefault(),
      capacity: this.cfg.compute.maxConcurrentSessions,
      expiry: nowEpoch + this.cfg.offers.maxLeaseEpochs,
    };

    const td = offerTypedData({ offer, shell_registry_address: this.cfg.chain.deployment.shellRegistry });

    const signer = privateKeyToAccount(this.offerSigner.privateKey);
    const signature = (await signer.signTypedData(td as any)) as Hex;

    this.bundle = {
      offer,
      signature,
      offerSignerAddress: signer.address,
      publishedAtMs: Date.now(),
    };
    this.pricing = { pricePerSU, lastPublishedAtMs: this.bundle.publishedAtMs };
    return this.bundle;
  }

  async revoke(): Promise<OfferBundle> {
    // "Revoke" by publishing an immediately-expired offer with bumped nonce.
    const chainId = this.cfg.chain.chainId;
    const shellId = this.cfg.identity.shellId ?? (this.db.getMeta('shell_id') as Hex | undefined);
    if (!shellId) throw new Error('cannot revoke offer: shell_id not set');

    const nowEpoch = await this.nowEpoch();
    const nonce = this.getAndBumpNonce();
    const offer_id = offerId({ shell_id: shellId, nonce, chain_id: chainId });
    const signer = privateKeyToAccount(this.offerSigner.privateKey);

    const offer: Offer = {
      offer_id,
      shell_id: shellId,
      chain_id: chainId,
      nonce,
      price_per_SU: this.cfg.offers.basePricePerSU,
      escrow_asset: this.cfg.offers.asset,
      min_lease: this.cfg.offers.minLeaseEpochs,
      max_SU: BigInt(this.cfg.compute.maxSUPerEpoch),
      assurance_tier: 0,
      capability_hash: bytes32Zero(),
      policy_tags: '0x',
      region: regionDefault(),
      capacity: 0,
      expiry: nowEpoch, // expire immediately
    };

    const td = offerTypedData({ offer, shell_registry_address: this.cfg.chain.deployment.shellRegistry });
    const signature = (await signer.signTypedData(td as any)) as Hex;

    this.bundle = {
      offer,
      signature,
      offerSignerAddress: signer.address,
      publishedAtMs: Date.now(),
    };
    return this.bundle;
  }
}

