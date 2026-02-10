import { describe, expect, it } from 'vitest';

import { computeDynamicPrice } from '../src/offers/pricing.js';

describe('dynamic pricing', () => {
  it('applies premium above 80% utilization with hysteresis', () => {
    const prev = { pricePerSU: 100n, lastPublishedAtMs: 0 };
    const next = computeDynamicPrice({
      cfg: {
        basePricePerSU: 100n,
        premiumMultiplierBps: 2000,
        enabled: true,
        maxConcurrentSessions: 10,
        minUpdateIntervalMs: 30_000,
      },
      activeSessions: 9,
      prev,
      nowMs: 60_000,
    });
    expect(next.pricePerSU).toEqual(120n);
  });

  it('does not republish more often than minUpdateIntervalMs', () => {
    const prev = { pricePerSU: 100n, lastPublishedAtMs: 50_000 };
    const next = computeDynamicPrice({
      cfg: {
        basePricePerSU: 100n,
        premiumMultiplierBps: 2000,
        enabled: true,
        maxConcurrentSessions: 10,
        minUpdateIntervalMs: 30_000,
      },
      activeSessions: 9,
      prev,
      nowMs: 60_000,
    });
    expect(next).toEqual(prev);
  });
});

