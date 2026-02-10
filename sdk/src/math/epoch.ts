export class EpochClock {
  public readonly genesis_time: bigint;
  public readonly epoch_length: bigint;

  constructor(genesis_time: bigint, epoch_length: bigint) {
    if (epoch_length <= 0n) throw new Error('EpochClock: epoch_length must be > 0');
    this.genesis_time = genesis_time;
    this.epoch_length = epoch_length;
  }

  epochAt(timestamp_sec: bigint): bigint {
    if (timestamp_sec <= this.genesis_time) return 0n;
    return (timestamp_sec - this.genesis_time) / this.epoch_length;
  }

  currentEpoch(): bigint {
    const now_sec = BigInt(Math.floor(Date.now() / 1000));
    return this.epochAt(now_sec);
  }

  epochStart(epoch: bigint): bigint {
    if (epoch < 0n) throw new Error('EpochClock: epoch must be >= 0');
    return this.genesis_time + epoch * this.epoch_length;
  }

  epochEnd(epoch: bigint): bigint {
    return this.epochStart(epoch + 1n) - 1n;
  }

  secondsRemaining(): bigint {
    const now_sec = BigInt(Math.floor(Date.now() / 1000));
    const end = this.epochEnd(this.epochAt(now_sec));
    if (end <= now_sec) return 0n;
    return end - now_sec;
  }
}

