import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Hex } from 'viem';

export type RecoveryEvent =
  | { type: 'RecoveryStarted'; ghost_id: Hex; attempt_id: bigint }
  | { type: 'RecoveryRotated'; ghost_id: Hex; attempt_id: bigint }
  | { type: 'RecoveryExpired'; ghost_id: Hex; attempt_id: bigint }
  | { type: 'RecoveryExited'; ghost_id: Hex };

export interface RecoveryEventSource {
  subscribe(cb: (evt: RecoveryEvent) => void): () => void;
}

export class RecoveryMonitor {
  private unsubscribe: (() => void) | undefined;

  constructor(
    private readonly deps: {
      ghost_id: Hex;
      dataDir: string;
      events: RecoveryEventSource;
      onRecoveryStarted?: (evt: Extract<RecoveryEvent, { type: 'RecoveryStarted' }>) => void;
      onRecoveryRotated?: (evt: Extract<RecoveryEvent, { type: 'RecoveryRotated' }>) => void;
      onRecoveryExpired?: (evt: Extract<RecoveryEvent, { type: 'RecoveryExpired' }>) => void;
      onRecoveryExited?: (evt: Extract<RecoveryEvent, { type: 'RecoveryExited' }>) => void;
    },
  ) {}

  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.deps.events.subscribe((evt) => void this.handle(evt));
  }

  stop(): void {
    if (!this.unsubscribe) return;
    this.unsubscribe();
    this.unsubscribe = undefined;
  }

  private async handle(evt: RecoveryEvent): Promise<void> {
    if (evt.ghost_id !== this.deps.ghost_id) return;

    // Persist minimal state for restart continuity (v1).
    await mkdir(this.deps.dataDir, { recursive: true });
    await writeFile(
      join(this.deps.dataDir, 'recovery_state.json'),
      JSON.stringify(
        {
          ghost_id: this.deps.ghost_id,
          last_event: evt.type,
          attempt_id: 'attempt_id' in evt ? evt.attempt_id.toString() : null,
          ts: Date.now(),
        },
        null,
        2,
      ),
    );

    switch (evt.type) {
      case 'RecoveryStarted':
        this.deps.onRecoveryStarted?.(evt);
        break;
      case 'RecoveryRotated':
        this.deps.onRecoveryRotated?.(evt);
        break;
      case 'RecoveryExpired':
        this.deps.onRecoveryExpired?.(evt);
        break;
      case 'RecoveryExited':
        this.deps.onRecoveryExited?.(evt);
        break;
      default: {
        const _exhaustive: never = evt;
        return _exhaustive;
      }
    }
  }
}

