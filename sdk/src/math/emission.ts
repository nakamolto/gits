import { bpsMul, mulDiv } from './q64.js';

const Q64_ONE = 1n << 64n;

export class EmissionSchedule {
  public readonly e0: bigint;
  public readonly e_tail: bigint;
  public readonly halving_interval: bigint;
  public readonly genesis_epoch: bigint;

  constructor(e0: bigint, e_tail: bigint, halving_interval: bigint, genesis_epoch: bigint) {
    if (halving_interval <= 0n) throw new Error('EmissionSchedule: halving_interval must be > 0');
    this.e0 = e0;
    this.e_tail = e_tail;
    this.halving_interval = halving_interval;
    this.genesis_epoch = genesis_epoch;
  }

  // Q64.64 decay factor (1.0 at genesis, halves every halving_interval epochs).
  decayQ(epoch: bigint): bigint {
    const e = epoch <= this.genesis_epoch ? this.genesis_epoch : epoch;
    const k = (e - this.genesis_epoch) / this.halving_interval;
    if (k >= 64n) return 0n;
    return Q64_ONE >> k;
  }

  scheduledEmission(epoch: bigint): bigint {
    const decay_q = this.decayQ(epoch);
    const decayed = mulDiv(this.e0, decay_q, Q64_ONE);
    return decayed + this.e_tail;
  }

  grossEmission(epoch: bigint, utilization_q: bigint): bigint {
    const e_sched = this.scheduledEmission(epoch);
    return mulDiv(e_sched, utilization_q, Q64_ONE);
  }

  netEmission(epoch: bigint, utilization_q: bigint, sink_bps: bigint): bigint {
    const gross = this.grossEmission(epoch, utilization_q);
    const withheld = bpsMul(gross, sink_bps);
    return gross - withheld;
  }
}

