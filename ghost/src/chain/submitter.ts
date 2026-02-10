import { EventEmitter } from 'node:events';

import type { Address, Hex } from 'viem';
import type { PublicClient, WalletClient } from 'viem';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTransientError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    msg.includes('timeout') ||
    msg.includes('ECONNRESET') ||
    msg.includes('ETIMEDOUT') ||
    msg.includes('429') ||
    msg.toLowerCase().includes('rate')
  );
}

function isNonceError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
  return msg.includes('nonce') || msg.includes('replacement transaction underpriced');
}

class Mutex {
  private tail: Promise<void> = Promise.resolve();

  async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((r) => (release = r));
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

export type TxSubmitterOptions = {
  maxGas?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  confirmations?: number;
  retries?: number;
  backoffMs?: { base: number; max: number };
};

export type TxSentEvent = { hash: Hex; nonce: number; to?: Address };
export type TxConfirmedEvent = { hash: Hex; receipt: unknown };
export type TxFailedEvent = { error: unknown };

export class TxSubmitter {
  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly opts: Required<TxSubmitterOptions>;

  private readonly emitter = new EventEmitter();

  private readonly nonceMutexByFrom = new Map<string, Mutex>();
  private readonly nextNonceByFrom = new Map<string, number>();

  constructor(args: { publicClient: PublicClient; walletClient: WalletClient; opts?: TxSubmitterOptions }) {
    this.publicClient = args.publicClient;
    this.walletClient = args.walletClient;
    this.opts = {
      maxGas: args.opts?.maxGas ?? 8_000_000n,
      maxFeePerGas: args.opts?.maxFeePerGas ?? 0n,
      maxPriorityFeePerGas: args.opts?.maxPriorityFeePerGas ?? 0n,
      confirmations: args.opts?.confirmations ?? 1,
      retries: args.opts?.retries ?? 3,
      backoffMs: args.opts?.backoffMs ?? { base: 250, max: 5_000 },
    };
  }

  on(event: 'txSent', handler: (e: TxSentEvent) => void): () => void;
  on(event: 'txConfirmed', handler: (e: TxConfirmedEvent) => void): () => void;
  on(event: 'txFailed', handler: (e: TxFailedEvent) => void): () => void;
  on(event: string, handler: (e: any) => void): () => void {
    this.emitter.on(event, handler);
    return () => this.emitter.off(event, handler);
  }

  async submit(request: any): Promise<Hex> {
    const from = (request.account?.address ?? request.from) as Address | undefined;
    if (!from) throw new Error('TxSubmitter: request.account.address (or from) is required');

    const mutex = this.nonceMutexByFrom.get(from) ?? new Mutex();
    this.nonceMutexByFrom.set(from, mutex);

    const sendOnce = (): Promise<{ hash: Hex; nonce: number }> =>
      mutex.runExclusive(async () => {
        let nonce = this.nextNonceByFrom.get(from);
        if (nonce == null) {
          nonce = await this.publicClient.getTransactionCount({ address: from, blockTag: 'pending' });
        }

        const next = nonce + 1;
        this.nextNonceByFrom.set(from, next);

        try {
          const enriched = await this.enrichRequest(request);
          const hash = (await this.walletClient.sendTransaction({ ...enriched, nonce })) as Hex;
          this.emitter.emit('txSent', { hash, nonce, to: request.to } satisfies TxSentEvent);
          return { hash, nonce };
        } catch (err) {
          if (isNonceError(err)) {
            // Reset local nonce tracking so the retry refreshes from chain.
            this.nextNonceByFrom.delete(from);
          } else {
            // If send failed, don't reserve the nonce permanently.
            this.nextNonceByFrom.set(from, nonce);
          }
          throw err;
        }
      });

    let attempt = 0;
    while (true) {
      attempt++;
      try {
        const { hash } = await sendOnce();

        // Confirm outside the nonce mutex.
        const receipt = await this.publicClient.waitForTransactionReceipt({
          hash,
          confirmations: this.opts.confirmations,
        });
        this.emitter.emit('txConfirmed', { hash, receipt } satisfies TxConfirmedEvent);
        return hash;
      } catch (err) {
        if (attempt >= this.opts.retries + 1 || (!isTransientError(err) && !isNonceError(err))) {
          this.emitter.emit('txFailed', { error: err } satisfies TxFailedEvent);
          throw err;
        }

        const backoff = Math.min(this.opts.backoffMs.base * 2 ** (attempt - 1), this.opts.backoffMs.max);
        await sleep(backoff);
      }
    }
  }

  private async enrichRequest(request: any): Promise<any> {
    const enriched: any = { ...request };

    if (enriched.gas == null) {
      const estimated = await this.publicClient.estimateGas(enriched);
      enriched.gas = estimated > this.opts.maxGas ? this.opts.maxGas : estimated;
    } else if (typeof enriched.gas === 'bigint' && enriched.gas > this.opts.maxGas) {
      enriched.gas = this.opts.maxGas;
    }

    // Optional fee ceilings.
    if (this.opts.maxFeePerGas > 0n && enriched.maxFeePerGas == null) enriched.maxFeePerGas = this.opts.maxFeePerGas;
    if (this.opts.maxPriorityFeePerGas > 0n && enriched.maxPriorityFeePerGas == null) {
      enriched.maxPriorityFeePerGas = this.opts.maxPriorityFeePerGas;
    }

    return enriched;
  }
}
