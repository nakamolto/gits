#!/usr/bin/env node
import { Command } from 'commander';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { DEFAULT_CONFIG_PATH, loadGhostConfig } from './config/config.js';
import { GhostDaemon } from './daemon.js';
import { GhostDB } from './storage/db.js';

type PidFile = { pid: number; started_at: number; ghost_id?: string };

async function writePidFile(dataDir: string, pidFile: PidFile): Promise<void> {
  await fs.mkdir(dataDir, { recursive: true });
  await fs.writeFile(path.join(dataDir, 'ghost.pid'), JSON.stringify(pidFile), 'utf8');
}

async function readPidFile(dataDir: string): Promise<PidFile | undefined> {
  try {
    const txt = await fs.readFile(path.join(dataDir, 'ghost.pid'), 'utf8');
    return JSON.parse(txt) as PidFile;
  } catch {
    return undefined;
  }
}

function notImplemented(cmd: string): never {
  throw new Error(`${cmd}: not implemented in core infra (module pending)`);
}

const program = new Command();
program.name('gits-ghost').description('GITS Ghost daemon').version('0.0.0');

program
  .command('init')
  .description('Create a starter ghost.toml config')
  .option('-c, --config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .action(async (opts) => {
    const configPath = opts.config as string;

    const example = `# ~/.gits/ghost.toml
# Minimal config. Fill in values from your deployment.

ghostId = "0x..." # 32-byte hex
walletAddress = "0x..."
identityKeyPath = "~/.gits/ghost/identity.key"

dataDir = "~/.gits/ghost"

rpcUrl = "https://..."

[deployment]
chain_id = 0
# Addresses
# git_token = "0x..."
# shell_registry = "0x..."
# ghost_registry = "0x..."
# session_manager = "0x..."
# receipt_manager = "0x..."
# rewards_manager = "0x..."
# verifier_registry = "0x..."

[telemetry]
logLevel = "info"
# healthPort = 8787
`;

    await fs.mkdir(path.dirname(configPath), { recursive: true });
    try {
      await fs.writeFile(configPath, example, { flag: 'wx' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`init: failed to write ${configPath}: ${msg}`);
    }

    process.stdout.write(`Wrote starter config: ${configPath}\n`);
  });

program
  .command('start')
  .description('Start the Ghost daemon (foreground)')
  .option('-c, --config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .option('--passphrase <pass>', 'Identity key passphrase (or set GITS_GHOST_PASSPHRASE)')
  .action(async (opts) => {
    const daemon = new GhostDaemon({ configPath: opts.config as string });
    await daemon.start({ identityPassphrase: opts.passphrase as string | undefined });

    const status = daemon.status();
    if (status.ghost_id) {
      const cfg = await loadGhostConfig(opts.config as string);
      await writePidFile(cfg.dataDir, { pid: process.pid, started_at: Date.now(), ghost_id: status.ghost_id });
    }

    const shutdown = async (signal: string) => {
      process.stdout.write(`\nReceived ${signal}, shutting down...\n`);
      try {
        await daemon.stop();
      } finally {
        process.exit(0);
      }
    };

    process.on('SIGINT', () => void shutdown('SIGINT'));
    process.on('SIGTERM', () => void shutdown('SIGTERM'));

    // Keep process alive.
    await new Promise(() => undefined);
  });

program
  .command('stop')
  .description('Stop a running Ghost daemon (best-effort via PID file)')
  .option('-c, --config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .action(async (opts) => {
    const cfg = await loadGhostConfig(opts.config as string);
    const pidFile = await readPidFile(cfg.dataDir);
    if (!pidFile) throw new Error('stop: PID file not found; daemon may not be running');

    try {
      process.kill(pidFile.pid, 'SIGTERM');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`stop: failed to signal pid ${pidFile.pid}: ${msg}`);
    }

    process.stdout.write(`Sent SIGTERM to pid ${pidFile.pid}\n`);
  });

program
  .command('status')
  .description('Show daemon status (local DB + config)')
  .option('-c, --config <path>', 'Config path', DEFAULT_CONFIG_PATH)
  .action(async (opts) => {
    const cfg = await loadGhostConfig(opts.config as string);
    const db = await GhostDB.open(cfg.dataDir);

    const cursor = db.getChainCursor();
    const sessions = db.listSessions().length;
    db.close();

    process.stdout.write(`ghost_id: ${cfg.ghostId}\n`);
    process.stdout.write(`wallet:   ${cfg.walletAddress}\n`);
    process.stdout.write(`cursor:   ${cursor}\n`);
    process.stdout.write(`sessions: ${sessions}\n`);
  });

// Surface area for downstream modules (stubbed here).
for (const name of [
  'register',
  'open-session',
  'close-session',
  'renew-lease',
  'migrate',
  'policy',
  'checkpoint',
  'vault-status',
  'recovery-config',
  'recovery-set',
  'bond',
  'unbond',
  'sessions',
  'shell-reputation',
  'intervals',
] as const) {
  program
    .command(name)
    .description('Command provided by a higher-level module')
    .option('-c, --config <path>', 'Config path', DEFAULT_CONFIG_PATH)
    .action(async () => {
      notImplemented(name);
    });
}

await program.parseAsync(process.argv);
