import type { DiscoveredOffer, MigrationContext, MigrationDecision, MigrationPlan, RankedDestination } from './types.js';

export class NoViableOffersError extends Error {
  constructor(message = 'no viable destination offers') {
    super(message);
    this.name = 'NoViableOffersError';
  }
}

function bigintToSafeNumber(x: bigint): number {
  const max = BigInt(Number.MAX_SAFE_INTEGER);
  if (x >= max) return Number.MAX_SAFE_INTEGER;
  if (x <= -max) return -Number.MAX_SAFE_INTEGER;
  return Number(x);
}

export function shouldMigrate(context: MigrationContext): MigrationDecision {
  const now = context.nowEpoch;
  const { anomalies, preferences, current } = context;

  if (anomalies.level === 'emergency') {
    return {
      migrate: true,
      urgency: 'emergency',
      when: now,
      reason: anomalies.reasons.length ? `emergency anomaly: ${anomalies.reasons.join('; ')}` : 'emergency anomaly',
    };
  }

  if (anomalies.level === 'urgent') {
    return {
      migrate: true,
      urgency: 'urgent',
      when: now,
      reason: anomalies.reasons.length ? `urgent anomaly: ${anomalies.reasons.join('; ')}` : 'urgent anomaly',
    };
  }

  if (current.leaseExpiryEpoch <= now + preferences.migrationBufferEpochs) {
    return {
      migrate: true,
      urgency: 'urgent',
      when: now,
      reason: 'lease approaching expiry',
    };
  }

  const tenureEnd = current.residencyStartEpoch + current.tenureLimitEpochs;
  if (tenureEnd <= now + preferences.tenureBufferEpochs) {
    return {
      migrate: true,
      urgency: 'routine',
      when: now,
      reason: 'tenure approaching limit',
    };
  }

  if (current.assuranceTier < preferences.preferredAssuranceTier) {
    return {
      migrate: true,
      urgency: 'routine',
      when: now + 1n,
      reason: 'assurance tier below preference',
    };
  }

  const observedPrice = current.observedPricePerSU ?? current.pricePerSU;
  if (observedPrice > preferences.maxPricePerSU) {
    return {
      migrate: true,
      urgency: 'routine',
      when: now + 1n,
      reason: 'price above maximum',
    };
  }

  const tolBps = BigInt(Math.max(0, Math.min(10000, preferences.priceIncreaseToleranceBps)));
  if (tolBps > 0n && current.pricePerSU > 0n) {
    const allowed = (current.pricePerSU * (10000n + tolBps)) / 10000n;
    if (observedPrice > allowed) {
      return {
        migrate: true,
        urgency: 'routine',
        when: now + 1n,
        reason: 'price increased beyond tolerance',
      };
    }
  }

  return {
    migrate: false,
    urgency: 'routine',
    when: now,
    reason: 'no migration triggers',
  };
}

export function scoreOffer(args: {
  discovered: DiscoveredOffer;
  context: MigrationContext;
  reputation: number;
}): number {
  const { discovered, context, reputation } = args;
  const { offer } = discovered;
  const prefs = context.preferences;

  if (offer.escrow_asset !== prefs.asset) return Number.NEGATIVE_INFINITY;
  if (offer.price_per_SU > prefs.maxPricePerSU) return Number.NEGATIVE_INFINITY;
  if (offer.assurance_tier < prefs.minAssuranceTier) return Number.NEGATIVE_INFINITY;
  if (offer.max_SU < prefs.requiredMaxSU) return Number.NEGATIVE_INFINITY;
  if (prefs.blacklistShellIds.includes(offer.shell_id)) return Number.NEGATIVE_INFINITY;

  // Price vs maxPricePerSU (lower is better).
  let priceScore = 0;
  if (prefs.maxPricePerSU === 0n) {
    priceScore = offer.price_per_SU === 0n ? 1_000_000 : 0;
  } else {
    const diff = prefs.maxPricePerSU - offer.price_per_SU;
    const scaled = (diff * 1_000_000n) / prefs.maxPricePerSU;
    priceScore = Math.max(0, bigintToSafeNumber(scaled));
  }

  // Assurance tier vs preference.
  const assuranceScore = (offer.assurance_tier - prefs.minAssuranceTier) * 1_000_000;
  const preferredBonus = offer.assurance_tier >= prefs.preferredAssuranceTier ? 500_000 : 0;

  // Capacity slack (small bonus).
  const slack = offer.max_SU - prefs.requiredMaxSU;
  const capacityScore = slack > 0n ? bigintToSafeNumber(slack * 1000n) : 0;

  // Local Shell reputation.
  const reputationScore = reputation * 10_000;

  // Prefer same operator if configured.
  const sameOperator =
    prefs.preferSameOperator &&
    Boolean(discovered.operator) &&
    Boolean(context.current.operator) &&
    discovered.operator === context.current.operator
      ? 250_000
      : 0;

  return priceScore + assuranceScore + preferredBonus + capacityScore + reputationScore + sameOperator;
}

export function plan(
  decision: MigrationDecision,
  ranked: RankedDestination[],
  nowEpoch: bigint,
  estimatedBundleBytes: bigint,
): MigrationPlan {
  const primary = ranked[0];
  if (!primary) throw new NoViableOffersError();

  const fallbacks = ranked.slice(1, 3);
  const migrateAtEpoch = decision.urgency === 'routine' ? decision.when : nowEpoch;

  return {
    decision,
    primary,
    fallbacks,
    migrateAtEpoch,
    estimatedBundleBytes,
  };
}

