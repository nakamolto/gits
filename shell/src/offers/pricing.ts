export interface PricingState {
  pricePerSU: bigint;
  lastPublishedAtMs: number;
}

export interface DynamicPricingConfig {
  basePricePerSU: bigint;
  premiumMultiplierBps: number;
  enabled: boolean;
  maxConcurrentSessions: number;
  minUpdateIntervalMs: number;
}

export function computeDynamicPrice(args: {
  cfg: DynamicPricingConfig;
  activeSessions: number;
  prev: PricingState;
  nowMs: number;
}): PricingState {
  const { cfg, activeSessions, prev, nowMs } = args;
  if (!cfg.enabled) return prev;
  if (nowMs - prev.lastPublishedAtMs < cfg.minUpdateIntervalMs) return prev;

  const util = cfg.maxConcurrentSessions === 0 ? 0 : activeSessions / cfg.maxConcurrentSessions;
  let nextPrice = cfg.basePricePerSU;

  if (util > 0.8) {
    nextPrice = (cfg.basePricePerSU * BigInt(10_000 + cfg.premiumMultiplierBps)) / 10_000n;
  } else if (util < 0.2) {
    nextPrice = cfg.basePricePerSU;
  } else {
    // Mid-band: stick to current price to avoid spam.
    nextPrice = prev.pricePerSU;
  }

  if (nextPrice === prev.pricePerSU) return prev;
  return { pricePerSU: nextPrice, lastPublishedAtMs: nowMs };
}

