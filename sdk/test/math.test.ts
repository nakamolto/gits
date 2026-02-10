import { describe, expect, it, vi } from 'vitest';

import { EpochClock } from '../src/math/epoch.js';
import { EmissionSchedule } from '../src/math/emission.js';
import { bpsMul, mulDiv, mulQ64, q64ToDecimal, toQ64 } from '../src/math/q64.js';

describe('Q64.64 helpers', () => {
  it('toQ64(1/2) == 2^63', () => {
    expect(toQ64(1n, 2n)).toBe(1n << 63n);
  });

  it('mulQ64(0.5 * 0.5) == 0.25', () => {
    const half = toQ64(1n, 2n);
    const quarter = mulQ64(half, half);
    expect(quarter).toBe(1n << 62n);
    expect(q64ToDecimal(quarter, 4)).toBe('0.2500');
  });

  it('mulDiv and bpsMul', () => {
    expect(mulDiv(10n, 3n, 2n)).toBe(15n);
    expect(bpsMul(1_000_000n, 250n)).toBe(25_000n);
  });
});

describe('EpochClock', () => {
  it('epochAt / boundaries', () => {
    const c = new EpochClock(1000n, 10n);
    expect(c.epochAt(1000n)).toBe(0n);
    expect(c.epochAt(1009n)).toBe(0n);
    expect(c.epochAt(1010n)).toBe(1n);

    expect(c.epochStart(0n)).toBe(1000n);
    expect(c.epochEnd(0n)).toBe(1009n);
    expect(c.epochStart(1n)).toBe(1010n);
    expect(c.epochEnd(1n)).toBe(1019n);
  });

  it('secondsRemaining (fake timers)', () => {
    vi.useFakeTimers();
    try {
      // Now = 1037 => epoch 3 (starts 1030, ends 1039), remaining = 2 seconds.
      vi.setSystemTime(new Date(1037_000));
      const c = new EpochClock(1000n, 10n);
      expect(c.secondsRemaining()).toBe(2n);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EmissionSchedule', () => {
  it('scheduledEmission halves on interval', () => {
    const s = new EmissionSchedule(1000n, 10n, 2n, 0n);

    expect(s.scheduledEmission(0n)).toBe(1010n);
    expect(s.scheduledEmission(1n)).toBe(1010n);
    expect(s.scheduledEmission(2n)).toBe(510n);
    expect(s.scheduledEmission(3n)).toBe(510n);
    expect(s.scheduledEmission(4n)).toBe(260n);
  });

  it('grossEmission and netEmission use utilizationQ and sinkBps', () => {
    const s = new EmissionSchedule(1000n, 0n, 10n, 0n);
    const half = toQ64(1n, 2n);

    // epoch 0: E_sched=1000, utilization=0.5 => gross=500
    expect(s.grossEmission(0n, half)).toBe(500n);
    // 10% sink => net=450
    expect(s.netEmission(0n, half, 1000n)).toBe(450n);
  });
});

