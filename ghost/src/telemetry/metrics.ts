export type MetricsSnapshot = {
  counters: Record<string, number>;
  gauges: Record<string, number>;
};

export class Metrics {
  private readonly counters: Record<string, number> = Object.create(null);
  private readonly gauges: Record<string, number> = Object.create(null);

  inc(name: string, by: number = 1): void {
    if (!Number.isFinite(by)) throw new Error('Metrics: increment must be finite');
    this.counters[name] = (this.counters[name] ?? 0) + by;
  }

  setGauge(name: string, value: number): void {
    if (!Number.isFinite(value)) throw new Error('Metrics: gauge value must be finite');
    this.gauges[name] = value;
  }

  snapshot(): MetricsSnapshot {
    return {
      counters: { ...this.counters },
      gauges: { ...this.gauges },
    };
  }
}
