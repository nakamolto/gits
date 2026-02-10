import { afterEach, describe, expect, it, vi } from 'vitest';

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as net from 'node:net';

import { GenericAgentClient } from '../src/agent-integration/generic-agent.js';
import { LifecycleManager } from '../src/agent-integration/lifecycle-hooks.js';
import { GITSSkill } from '../src/agent-integration/openclaw-plugin.js';

function tmpSocketPath(name: string): string {
  return path.join(os.tmpdir(), `gits-${name}-${process.pid}-${Math.random().toString(16).slice(2)}.sock`);
}

async function startTcpServer(
  handler: (req: unknown) => unknown | Promise<unknown>,
): Promise<{ server: net.Server; port: number }> {
  const server = net.createServer((socket) => {
    let buf = '';
    socket.on('data', async (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      const req = JSON.parse(line);
      const resp = await handler(req);
      socket.write(JSON.stringify(resp) + '\n');
      socket.end();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('unexpected server address');
  return { server, port: addr.port };
}

async function startUnixServer(
  socketPath: string,
  handler: (req: unknown) => unknown | Promise<unknown>,
): Promise<{ server: net.Server }> {
  const server = net.createServer((socket) => {
    let buf = '';
    socket.on('data', async (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      const req = JSON.parse(line);
      const resp = await handler(req);
      socket.write(JSON.stringify(resp) + '\n');
      socket.end();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve());
  });

  return { server };
}

async function closeServer(server: net.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

describe('GenericAgentClient (NDJSON)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('roundtrips all message types over TCP', async () => {
    const seen: unknown[] = [];
    const stateBytes = new Uint8Array([1, 2, 3, 4, 250, 251, 252]);
    const stateB64 = Buffer.from(stateBytes).toString('base64');
    const setStateBytes = new Uint8Array([9, 9, 9]);
    const setStateB64 = Buffer.from(setStateBytes).toString('base64');

    const { server, port } = await startTcpServer(async (req) => {
      seen.push(req);
      const r = req as { type: string; data?: string; shell_id?: string };
      switch (r.type) {
        case 'flush_state':
          return { type: 'flush_state_ack' };
        case 'reload_state':
          return { type: 'reload_state_ack' };
        case 'get_state':
          return { type: 'state_data', data: stateB64 };
        case 'set_state':
          return { type: 'set_state_ack' };
        case 'migration_start':
          return { type: 'migration_start_ack' };
        case 'migration_complete':
          return { type: 'migration_complete_ack' };
        case 'recovery_start':
          return { type: 'recovery_start_ack' };
        case 'recovery_complete':
          return { type: 'recovery_complete_ack' };
        default:
          throw new Error(`unexpected type: ${r.type}`);
      }
    });

    try {
      const client = new GenericAgentClient({ host: '127.0.0.1', port, timeoutMs: 1000 });

      await client.flushState();
      await client.reloadState();
      const st = await client.getState();
      await client.setState(setStateBytes);
      await client.onMigrationStart();
      await client.onMigrationComplete('0xabc' as `0x${string}`);
      await client.onRecoveryStart();
      await client.onRecoveryComplete();

      expect(Array.from(st)).toEqual(Array.from(stateBytes));

      const types = (seen as Array<{ type: string }>).map((m) => m.type);
      expect(types).toEqual([
        'flush_state',
        'reload_state',
        'get_state',
        'set_state',
        'migration_start',
        'migration_complete',
        'recovery_start',
        'recovery_complete',
      ]);

      const setStateMsg = seen.find((m) => (m as { type?: string }).type === 'set_state') as
        | { type: 'set_state'; data?: string }
        | undefined;
      expect(setStateMsg?.data).toBe(setStateB64);

      const migCompleteMsg = seen.find((m) => (m as { type?: string }).type === 'migration_complete') as
        | { type: 'migration_complete'; shell_id?: string }
        | undefined;
      expect(migCompleteMsg?.shell_id).toBe('0xabc');
    } finally {
      await closeServer(server);
    }
  });

  it('roundtrips over Unix domain socket', async () => {
    const socketPath = tmpSocketPath('agent');
    const seen: unknown[] = [];

    const { server } = await startUnixServer(socketPath, async (req) => {
      seen.push(req);
      const r = req as { type: string };
      if (r.type !== 'flush_state') throw new Error(`unexpected type: ${r.type}`);
      return { type: 'flush_state_ack' };
    });

    try {
      const client = new GenericAgentClient({ socketPath, timeoutMs: 1000 });
      await client.flushState();
      expect((seen[0] as { type: string }).type).toBe('flush_state');
    } finally {
      await closeServer(server);
      try {
        fs.unlinkSync(socketPath);
      } catch {
        // ignore
      }
    }
  });

  it('times out and proceeds if the agent does not respond', async () => {
    const server = net.createServer((socket) => {
      // Accept connection, read, then never respond.
      socket.on('data', () => {});
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });

    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('unexpected server address');
    const port = addr.port;

    try {
      const client = new GenericAgentClient({ host: '127.0.0.1', port, timeoutMs: 50 });

      const t0 = Date.now();
      await client.flushState();
      const dt = Date.now() - t0;
      expect(dt).toBeLessThan(500);

      const state = await client.getState();
      expect(state).toBeInstanceOf(Uint8Array);
      expect(state.length).toBe(0);
    } finally {
      await closeServer(server);
    }
  });
});

describe('LifecycleManager', () => {
  it('preMigration calls onMigrationStart then flushState', async () => {
    const integration = {
      flushState: vi.fn(async () => {}),
      reloadState: vi.fn(async () => {}),
      getState: vi.fn(async () => new Uint8Array()),
      setState: vi.fn(async () => {}),
      onMigrationStart: vi.fn(async () => {}),
      onMigrationComplete: vi.fn(async () => {}),
      onRecoveryStart: vi.fn(async () => {}),
      onRecoveryComplete: vi.fn(async () => {}),
    };

    const lm = new LifecycleManager();
    lm.setIntegration(integration);

    await lm.preMigration();

    const a = integration.onMigrationStart.mock.invocationCallOrder[0];
    const b = integration.flushState.mock.invocationCallOrder[0];
    expect(a).toBeLessThan(b);
  });

  it('postMigration calls reloadState then onMigrationComplete', async () => {
    const integration = {
      flushState: vi.fn(async () => {}),
      reloadState: vi.fn(async () => {}),
      getState: vi.fn(async () => new Uint8Array()),
      setState: vi.fn(async () => {}),
      onMigrationStart: vi.fn(async () => {}),
      onMigrationComplete: vi.fn(async () => {}),
      onRecoveryStart: vi.fn(async () => {}),
      onRecoveryComplete: vi.fn(async () => {}),
    };

    const lm = new LifecycleManager();
    lm.setIntegration(integration);

    await lm.postMigration('0x123' as `0x${string}`);

    const a = integration.reloadState.mock.invocationCallOrder[0];
    const b = integration.onMigrationComplete.mock.invocationCallOrder[0];
    expect(a).toBeLessThan(b);
  });
});

describe('OpenClaw plugin wiring', () => {
  it('delegates lifecycle methods and exposes migration/policy requests', async () => {
    const callbacks = {
      init: vi.fn(async () => {}),
      tick: vi.fn(async () => {}),
      shutdown: vi.fn(async () => {}),
      requestMigration: vi.fn(async () => {}),
      requestPolicyChange: vi.fn(async () => {}),
    };

    const skill = new GITSSkill(callbacks);

    const agent = { foo: 'bar' };
    await skill.onLoad(agent);
    await skill.onTick();
    await skill.requestMigration('reason');
    await skill.requestPolicyChange({ delta: 1 });
    await skill.onShutdown();

    expect(callbacks.init).toHaveBeenCalledWith(agent);
    expect(callbacks.tick).toHaveBeenCalledTimes(1);
    expect(callbacks.requestMigration).toHaveBeenCalledWith('reason');
    expect(callbacks.requestPolicyChange).toHaveBeenCalledWith({ delta: 1 });
    expect(callbacks.shutdown).toHaveBeenCalledTimes(1);
  });
});
