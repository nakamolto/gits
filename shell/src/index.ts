#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { Command } from 'commander';
import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { defaultShellConfigPath, loadShellConfig } from './config/config.js';
import { encryptPrivateKey, generateSessionKey, promptPassphrase, writeKeyfile, loadKeyFromFile } from './config/keys.js';
import { ShellDb } from './storage/db.js';
import { ChainSubmitter } from './chain/submitter.js';
import { registerShell, encodeIdentityPubkeyK1, encodeOfferSignerPubkeyK1 } from './registration/register.js';
import { beginUnbond, finalizeUnbond, bondSafeHaven, beginUnbondSafeHaven, finalizeUnbondSafeHaven } from './registration/bond.js';
import { setCertificate, revokeCertificate } from './registration/certificate.js';
import { ShellDaemon } from './daemon.js';

function expandHome(p: string): string {
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

async function writeIfMissing(filePath: string, content: string): Promise<void> {
  try {
    await fs.access(filePath);
  } catch {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content);
  }
}

function defaultConfigTemplate(): string {
  return `# ~/.gits/shell.toml

[identity]
# shellId = "0x..." # optional; normally set by register
identityKeyPath = "~/.gits/keys/identity.json"
offerSignerKeyPath = "~/.gits/keys/offer-signer.json"
recoveryKeyPath = "~/.gits/keys/recovery.json"
payoutAddress = "0x0000000000000000000000000000000000000000"

[chain]
rpcUrl = "http://127.0.0.1:8545"
chainId = 31337
gasStrategy = "auto"
# maxGasPrice = "0"

[chain.deployment]
gitToken = "0x0000000000000000000000000000000000000000"
shellRegistry = "0x0000000000000000000000000000000000000000"
ghostRegistry = "0x0000000000000000000000000000000000000000"
sessionManager = "0x0000000000000000000000000000000000000000"
receiptManager = "0x0000000000000000000000000000000000000000"
rewardsManager = "0x0000000000000000000000000000000000000000"
verifierRegistry = "0x0000000000000000000000000000000000000000"

[offers]
basePricePerSU = "1"
asset = "0x0000000000000000000000000000000000000000"
minLeaseEpochs = "1"
maxLeaseEpochs = "10"
dynamicPricing = false
premiumMultiplierBps = 2000

[compute]
maxConcurrentSessions = 4
maxSUPerEpoch = 100
heartbeatIntervalMs = 5000

[bond]
bondAsset = "0x0000000000000000000000000000000000000000"
bondAmount = "0"
safeHavenBondAmount = "0"

[storage]
dataDir = "~/.gits/shell-data"

[network]
listenHost = "127.0.0.1"
listenPort = 7777
heartbeatTransport = "uds"
heartbeatSocketPath = "~/.gits/heartbeat.sock"
`;
}

async function cmdInit(opts: { config?: string }): Promise<void> {
  const configPath = expandHome(opts.config ?? defaultShellConfigPath());
  await writeIfMissing(configPath, defaultConfigTemplate());

  const cfg = await loadShellConfig(configPath);

  const pass = await promptPassphrase('Keyfile passphrase');
  const identity = generateSessionKey();
  const offer = generateSessionKey();
  const recovery = generateSessionKey();

  await writeKeyfile(cfg.identity.identityKeyPath, encryptPrivateKey(pass, identity.privateKey));
  await writeKeyfile(cfg.identity.offerSignerKeyPath, encryptPrivateKey(pass, offer.privateKey));
  await writeKeyfile(cfg.identity.recoveryKeyPath, encryptPrivateKey(pass, recovery.privateKey));

  // Ensure storage dir exists.
  await fs.mkdir(expandHome(cfg.storage.dataDir), { recursive: true });
  console.error(`wrote ${configPath}`);
}

async function cmdRegister(opts: { config?: string }): Promise<void> {
  const cfg = await loadShellConfig(opts.config ?? defaultShellConfigPath());
  const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);

  const identityPass = await promptPassphrase('Identity key passphrase');
  const offerPass = await promptPassphrase('Offer signer key passphrase');

  const identityKey = await loadKeyFromFile({ purpose: 'identity', path: cfg.identity.identityKeyPath, passphrase: identityPass });
  const offerSignerKey = await loadKeyFromFile({ purpose: 'offer-signer', path: cfg.identity.offerSignerKeyPath, passphrase: offerPass });

  const chain = new ChainSubmitter({ cfg, identityPrivateKey: identityKey.privateKey });
  const res = await registerShell({ cfg, db, chain, identityKey, offerSignerKey });
  console.error(JSON.stringify(res, null, 2));
  db.close();
}

async function cmdStatus(opts: { config?: string }): Promise<void> {
  const cfg = await loadShellConfig(opts.config ?? defaultShellConfigPath());
  const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);
  const shellId = cfg.identity.shellId ?? db.getMeta('shell_id');
  const cursor = db.getChainCursor();
  console.error(
    JSON.stringify(
      {
        shellId,
        chainId: cfg.chain.chainId.toString(),
        lastBlock: cursor?.toString(),
        dataDir: cfg.storage.dataDir,
      },
      null,
      2,
    ),
  );
  db.close();
}

async function cmdStart(opts: { config?: string }): Promise<void> {
  const daemon = await ShellDaemon.create({ configPath: opts.config });
  await daemon.start();

  const shutdown = async () => {
    try {
      await daemon.stop();
    } finally {
      process.exit(0);
    }
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Keep the process alive.
  // eslint-disable-next-line no-constant-condition
  while (true) await new Promise((r) => setTimeout(r, 60_000));
}

async function withChain(cfgPath: string | undefined, fn: (cfg: any, db: ShellDb, chain: ChainSubmitter) => Promise<void>): Promise<void> {
  const cfg = await loadShellConfig(cfgPath ?? defaultShellConfigPath());
  const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);
  const pass = await promptPassphrase('Identity key passphrase');
  const identity = await loadKeyFromFile({ purpose: 'identity', path: cfg.identity.identityKeyPath, passphrase: pass });
  const chain = new ChainSubmitter({ cfg, identityPrivateKey: identity.privateKey });
  try {
    await fn(cfg, db, chain);
  } finally {
    db.close();
  }
}

function nextKeyPath(basePath: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  return `${basePath}.next.${ts}`;
}

async function main(): Promise<void> {
  const program = new Command();
  program.name('gits-shell').description('GITS Shell daemon').version('0.0.0');

  program.command('init').option('-c, --config <path>', 'config path').action(cmdInit);
  program.command('register').option('-c, --config <path>', 'config path').action(cmdRegister);
  program.command('start').option('-c, --config <path>', 'config path').action(cmdStart);
  program.command('stop').action(() => {
    console.error('v1: run in foreground; stop with SIGINT/SIGTERM');
  });
  program.command('status').option('-c, --config <path>', 'config path').action(cmdStatus);

  // Bond + cert management
  program
    .command('unbond')
    .requiredOption('--amount <amount>', 'amount (uint256)')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await beginUnbond({ chain, shellId, amount: BigInt(o.amount) });
        console.error(tx);
      });
    });

  program
    .command('unbond-finalize')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await finalizeUnbond({ chain, shellId });
        console.error(tx);
      });
    });

  program
    .command('bond-safehaven')
    .requiredOption('--amount <amount>', 'amount (uint256)')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await bondSafeHaven({ chain, shellId, amount: BigInt(o.amount) });
        console.error(tx);
      });
    });

  program
    .command('unbond-safehaven')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await beginUnbondSafeHaven({ chain, shellId });
        console.error(tx);
      });
    });

  program
    .command('unbond-safehaven-finalize')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await finalizeUnbondSafeHaven({ chain, shellId });
        console.error(tx);
      });
    });

  program
    .command('set-certificate')
    .requiredOption('--cert <hex>', 'cert_data hex')
    .requiredOption('--sigs <hex...>', 'verifier sigs hex list')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await setCertificate({ chain, shellId, certData: o.cert, sigsVerifiers: o.sigs });
        console.error(tx);
      });
    });

  program
    .command('revoke-certificate')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      await withChain(o.config, async (cfg, db, chain) => {
        const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const tx = await revokeCertificate({ chain, shellId });
        console.error(tx);
      });
    });

  // Key rotations (two-stage: propose now, swap keyfile after confirm).
  program
    .command('rotate-offer-key')
    .option('-c, --config <path>', 'config path')
    .option('--confirm', 'confirm pending offer-signer update (timelock must have elapsed)')
    .action(async (o: any) => {
      if (o.confirm) {
        await withChain(o.config, async (cfg, db, chain) => {
          const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
          if (!shellId) throw new Error('shell_id not set');
          const tx = await chain.confirmOfferSignerUpdate(shellId);
          console.error(tx);
        });
        return;
      }

      const cfg = await loadShellConfig(o.config ?? defaultShellConfigPath());
      const pass = await promptPassphrase('New offer-signer keyfile passphrase');
      const key = generateSessionKey();
      const outPath = nextKeyPath(expandHome(cfg.identity.offerSignerKeyPath));
      await writeKeyfile(outPath, encryptPrivateKey(pass, key.privateKey));

      await withChain(o.config, async (cfg2, db, chain) => {
        const shellId = (cfg2.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');
        const newSigner = privateKeyToAccount(key.privateKey);
        const newPub = encodeOfferSignerPubkeyK1(newSigner.address);
        const tx = await chain.proposeOfferSignerUpdate({ shellId, newOfferSignerPubkey: newPub });
        console.error(JSON.stringify({ tx, newKeyPath: outPath }, null, 2));
      });
    });

  program
    .command('rotate-identity-key')
    .option('-c, --config <path>', 'config path')
    .option('--confirm', 'confirm pending identity update (timelock must have elapsed)')
    .action(async (o: any) => {
      if (o.confirm) {
        await withChain(o.config, async (cfg, db, chain) => {
          const shellId = (cfg.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
          if (!shellId) throw new Error('shell_id not set');
          const tx = await chain.confirmIdentityKeyUpdate(shellId);
          console.error(tx);
        });
        return;
      }

      const cfg = await loadShellConfig(o.config ?? defaultShellConfigPath());
      const passNew = await promptPassphrase('New identity keyfile passphrase');
      const newKey = generateSessionKey();
      const outPath = nextKeyPath(expandHome(cfg.identity.identityKeyPath));
      await writeKeyfile(outPath, encryptPrivateKey(passNew, newKey.privateKey));

      await withChain(o.config, async (cfg2, db, chain) => {
        const shellId = (cfg2.identity.shellId ?? (db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) throw new Error('shell_id not set');

        const nonce = await chain.readShellKeyNonce(shellId);
        const newIdentity = privateKeyToAccount(newKey.privateKey);
        const newPub = encodeIdentityPubkeyK1(newIdentity.address);

        const TAG = keccak256(toBytes('GITS_SHELL_KEY_PROPOSE'));
        const digest = keccak256(
          encodeAbiParameters(
            [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes' }, { type: 'uint64' }, { type: 'uint256' }],
            [TAG, shellId, newPub, nonce, cfg2.chain.chainId],
          ),
        );

        // Proof is signed by current identity key (wallet used by ChainSubmitter).
        const proof = (await chain.account.sign({ hash: digest })) as Hex;
        const tx = await chain.proposeIdentityKeyUpdate({ shellId, newIdentityPubkey: newPub, proof });
        console.error(JSON.stringify({ tx, newKeyPath: outPath }, null, 2));
      });
    });

  // Read-only helpers
  program
    .command('sessions')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      const cfg = await loadShellConfig(o.config ?? defaultShellConfigPath());
      const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);
      const rows = db
        .raw()
        .prepare(
          `SELECT session_id, lower(hex(ghost_id)) AS ghost_id, lower(hex(shell_id)) AS shell_id, status, start_epoch, end_epoch
           FROM sessions
           ORDER BY session_id DESC
           LIMIT 100`,
        )
        .all();
      console.error(JSON.stringify(rows, null, 2));
      db.close();
    });

  program
    .command('receipts')
    .option('-c, --config <path>', 'config path')
    .action(async (o: any) => {
      const cfg = await loadShellConfig(o.config ?? defaultShellConfigPath());
      const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);
      const rows = db
        .raw()
        .prepare(
          `SELECT es.session_id, es.epoch, lower(hex(es.log_root)) AS log_root, es.su_delivered, es.candidate_id, es.receipt_status
           FROM epoch_summaries es
           ORDER BY es.epoch DESC, es.session_id DESC
           LIMIT 200`,
        )
        .all();
      console.error(JSON.stringify(rows, null, 2));
      db.close();
    });

  program
    .command('logs')
    .option('-c, --config <path>', 'config path')
    .option('--limit <n>', 'limit', '200')
    .action(async (o: any) => {
      const cfg = await loadShellConfig(o.config ?? defaultShellConfigPath());
      const db = await ShellDb.openAtDataDir(cfg.storage.dataDir);
      const limit = Math.max(1, Math.min(2_000, Number(o.limit)));
      const rows = db
        .raw()
        .prepare(
          `SELECT session_id, epoch, interval_index, vi, timestamp
           FROM intervals
           ORDER BY timestamp DESC
           LIMIT ?`,
        )
        .all(limit);
      console.error(JSON.stringify(rows, null, 2));
      db.close();
    });

  await program.parseAsync(process.argv);
}

await main();
