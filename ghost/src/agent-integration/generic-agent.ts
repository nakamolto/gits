import * as net from 'node:net';

export interface AgentIntegration {
  flushState(): Promise<void>;
  reloadState(): Promise<void>;
  getState(): Promise<Uint8Array>;
  setState(state: Uint8Array): Promise<void>;
  onMigrationStart(): Promise<void>;
  onMigrationComplete(newShellId: `0x${string}`): Promise<void>;
  onRecoveryStart(): Promise<void>;
  onRecoveryComplete(): Promise<void>;
}

type UnixSocketTransport = { socketPath: string };
type TcpTransport = { host: string; port: number };

export type GenericAgentClientOptions = {
  timeoutMs?: number;
} & (UnixSocketTransport | TcpTransport);

type Message =
  | { type: 'flush_state' }
  | { type: 'reload_state' }
  | { type: 'get_state' }
  | { type: 'set_state'; data: string }
  | { type: 'migration_start' }
  | { type: 'migration_complete'; shell_id: `0x${string}` }
  | { type: 'recovery_start' }
  | { type: 'recovery_complete' };

type Response =
  | { type: 'flush_state_ack' }
  | { type: 'reload_state_ack' }
  | { type: 'state_data'; data: string }
  | { type: 'set_state_ack' }
  | { type: 'migration_start_ack' }
  | { type: 'migration_complete_ack' }
  | { type: 'recovery_start_ack' }
  | { type: 'recovery_complete_ack' };

function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function decodeBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, 'base64'));
}

function safeParseJsonLine(line: string): unknown | undefined {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

function responseTypeIs<TType extends Response['type']>(
  resp: unknown,
  type: TType,
): resp is Extract<Response, { type: TType }> {
  return typeof resp === 'object' && resp !== null && 'type' in resp && (resp as { type: unknown }).type === type;
}

/**
 * GenericAgentClient speaks NDJSON over a local transport (UDS or TCP).
 *
 * Best-effort semantics: all methods resolve even if the agent is down or unresponsive.
 */
export class GenericAgentClient implements AgentIntegration {
  private readonly transport: UnixSocketTransport | TcpTransport;
  private readonly timeoutMs: number;

  constructor(opts: GenericAgentClientOptions) {
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    if ('socketPath' in opts) {
      this.transport = { socketPath: opts.socketPath };
    } else {
      this.transport = { host: opts.host, port: opts.port };
    }
  }

  async flushState(): Promise<void> {
    await this.sendAck({ type: 'flush_state' }, 'flush_state_ack');
  }

  async reloadState(): Promise<void> {
    await this.sendAck({ type: 'reload_state' }, 'reload_state_ack');
  }

  async getState(): Promise<Uint8Array> {
    const resp = await this.request({ type: 'get_state' });
    if (!responseTypeIs(resp, 'state_data')) return new Uint8Array();
    if (typeof resp.data !== 'string') return new Uint8Array();
    return decodeBase64(resp.data);
  }

  async setState(state: Uint8Array): Promise<void> {
    await this.sendAck({ type: 'set_state', data: encodeBase64(state) }, 'set_state_ack');
  }

  async onMigrationStart(): Promise<void> {
    await this.sendAck({ type: 'migration_start' }, 'migration_start_ack');
  }

  async onMigrationComplete(newShellId: `0x${string}`): Promise<void> {
    await this.sendAck({ type: 'migration_complete', shell_id: newShellId }, 'migration_complete_ack');
  }

  async onRecoveryStart(): Promise<void> {
    await this.sendAck({ type: 'recovery_start' }, 'recovery_start_ack');
  }

  async onRecoveryComplete(): Promise<void> {
    await this.sendAck({ type: 'recovery_complete' }, 'recovery_complete_ack');
  }

  private async sendAck(msg: Message, expectedType: Response['type']): Promise<void> {
    const resp = await this.request(msg);
    // Best-effort: ignore mismatched/missing ack.
    if (!responseTypeIs(resp, expectedType)) return;
  }

  private request(msg: Message): Promise<unknown | undefined> {
    const timeoutMs = this.timeoutMs;

    return new Promise((resolve) => {
      let done = false;
      let socket: net.Socket | undefined;
      let timeoutId: NodeJS.Timeout | undefined;
      let buffer = '';

      const finish = (value: unknown | undefined) => {
        if (done) return;
        done = true;
        cleanup();
        resolve(value);
      };

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        if (!socket) return;
        socket.removeAllListeners('connect');
        socket.removeAllListeners('data');
        socket.removeAllListeners('error');
        socket.removeAllListeners('end');
        socket.removeAllListeners('close');
        if (!socket.destroyed) socket.destroy();
      };

      timeoutId = setTimeout(() => finish(undefined), timeoutMs);

      try {
        socket =
          'socketPath' in this.transport
            ? net.createConnection({ path: this.transport.socketPath })
            : net.createConnection({ host: this.transport.host, port: this.transport.port });
      } catch {
        finish(undefined);
        return;
      }

      socket.once('error', () => finish(undefined));

      socket.once('connect', () => {
        try {
          // One request per connection: write the NDJSON line and half-close.
          socket?.end(JSON.stringify(msg) + '\n');
        } catch {
          finish(undefined);
        }
      });

      const maybeFinishWithLine = (line: string) => {
        const parsed = safeParseJsonLine(line);
        finish(parsed);
      };

      socket.on('data', (chunk: Buffer) => {
        buffer += chunk.toString('utf8');
        const nl = buffer.indexOf('\n');
        if (nl === -1) return;
        const line = buffer.slice(0, nl);
        maybeFinishWithLine(line);
      });

      // If the agent closes without a trailing newline but sent some JSON, try to parse it.
      socket.once('end', () => {
        if (done) return;
        const line = buffer.trim();
        if (line.length === 0) finish(undefined);
        else maybeFinishWithLine(line);
      });

      socket.once('close', () => {
        if (done) return;
        const line = buffer.trim();
        if (line.length === 0) finish(undefined);
        else maybeFinishWithLine(line);
      });
    });
  }
}
