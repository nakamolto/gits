import http from 'node:http';
import { URL } from 'node:url';

import pino from 'pino';
import { encodeAbiParameters, isHex, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { loadShellConfig } from './config/config.js';
import { loadKeyFromFile, promptPassphrase } from './config/keys.js';
import { ChainListener } from './chain/listener.js';
import { ChainSubmitter } from './chain/submitter.js';
import { OfferManager } from './offers/offer-manager.js';
import { buildAndStoreReceiptTree } from './receipts/receipt-builder.js';
import { DAResponder } from './receipts/da-responder.js';
import { ReceiptSubmitter } from './receipts/receipt-submitter.js';
import { ShellDb } from './storage/db.js';
import { Metrics } from './telemetry/metrics.js';
import { buildHealthReport } from './telemetry/health.js';
import { HeartbeatService, NetHeartbeatServer } from './sessions/heartbeat.js';
import { IssuedSessionKeyStore, ShellSessionManager } from './sessions/session-manager.js';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function readJson(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(Buffer.from(c));
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  return JSON.parse(raw);
}

function writeJson(res: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  res.end(data);
}

function tagSessionKeyDigest(args: { chainId: bigint; shellId: Hex; pubkeyUncompressed: Hex; expiresAtMs: bigint }): Hex {
  const TAG = keccak256(toBytes('GITS_SHELL_SESSION_KEY'));
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes32' }, { type: 'bytes' }, { type: 'uint256' }],
      [TAG, args.chainId, args.shellId, args.pubkeyUncompressed, args.expiresAtMs],
    ),
  );
}

export class ShellDaemon {
  private readonly log = pino({ name: 'gits-shell' });

  private cfg!: Awaited<ReturnType<typeof loadShellConfig>>;
  private db!: ShellDb;
  private chain!: ChainSubmitter;
  private offerSignerKey!: Awaited<ReturnType<typeof loadKeyFromFile>>;
  private metrics!: Metrics;
  private heartbeat!: HeartbeatService;
  private heartbeatUds!: NetHeartbeatServer;
  private sessions!: ShellSessionManager;
  private issuedKeys!: IssuedSessionKeyStore;
  private offers!: OfferManager;
  private chainListener!: ChainListener;
  private daResponder!: DAResponder;
  private receiptSubmitter!: ReceiptSubmitter;

  private httpServer?: http.Server;
  private pricingTimer?: NodeJS.Timeout;
  private epochTimer?: NodeJS.Timeout;
  private intervalsPerEpoch = 0;

  static async create(args: { configPath?: string }): Promise<ShellDaemon> {
    const d = new ShellDaemon();
    await d.init(args.configPath);
    return d;
  }

  private async init(configPath?: string): Promise<void> {
    this.cfg = await loadShellConfig(configPath);
    this.db = await ShellDb.openAtDataDir(this.cfg.storage.dataDir);
    this.metrics = new Metrics();

    const identityPass = await promptPassphrase('Identity key passphrase');
    const offerPass = await promptPassphrase('Offer signer key passphrase');

    const identityKey = await loadKeyFromFile({ purpose: 'identity', path: this.cfg.identity.identityKeyPath, passphrase: identityPass });
    const offerSignerKey = await loadKeyFromFile({ purpose: 'offer-signer', path: this.cfg.identity.offerSignerKeyPath, passphrase: offerPass });
    this.offerSignerKey = offerSignerKey;

    this.chain = new ChainSubmitter({ cfg: this.cfg, identityPrivateKey: identityKey.privateKey });

    // Persist shell_id if provided in config.
    if (this.cfg.identity.shellId) this.db.setMeta('shell_id', this.cfg.identity.shellId);

    this.heartbeat = new HeartbeatService({ chainId: this.cfg.chain.chainId, db: this.db, metrics: this.metrics });
    this.heartbeatUds = new NetHeartbeatServer({ service: this.heartbeat, socketPath: this.cfg.network.heartbeatSocketPath });

    this.issuedKeys = new IssuedSessionKeyStore();
    this.sessions = new ShellSessionManager({ cfg: this.cfg, db: this.db, heartbeat: this.heartbeat, issuedKeys: this.issuedKeys });

    this.intervalsPerEpoch = await this.chain.readIntervalsPerEpoch().catch(() => 0);
    const bondReceipt = await this.chain.readReceiptBond().catch(() => 0n);
    this.daResponder = new DAResponder({
      db: this.db,
      chain: { publishReceiptLog: (a) => this.chain.publishReceiptLog({ sessionId: a.sessionId, epoch: a.epoch, candidateId: a.candidateId, encodedLog: a.encodedLog }) },
      metrics: this.metrics,
      intervalsPerEpoch: this.intervalsPerEpoch || 0,
    });
    this.receiptSubmitter = new ReceiptSubmitter({ db: this.db, chain: this.chain, bondReceipt });

    this.offers = new OfferManager({
      cfg: this.cfg,
      db: this.db,
      offerSigner: this.offerSignerKey,
      nowEpoch: () => this.chain.readCurrentEpoch(),
      readAssuranceTier: async () => {
        const shellId = (this.cfg.identity.shellId ?? (this.db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
        if (!shellId) return 0;
        return this.chain.readAssuranceTier(shellId);
      },
    });

    await this.offers.publish().catch((err) => this.log.warn({ err }, 'offer publish failed'));

    this.chainListener = new ChainListener({
      cfg: this.cfg,
      db: this.db,
      publicClient: this.chain.publicClient,
      logger: this.log,
      handlers: {
        onSessionOpened: async ({ ghostId, shellId, sessionId, txHash, paramsJson }) => {
          const keys = await this.chain.readSessionKeys(sessionId);
          this.sessions.onSessionOpened({
            sessionId,
            ghostId,
            shellId,
            ghostSessionKey: keys.ghostKey,
            shellSessionKey: keys.shellKey,
            paramsJson,
          });
          this.offers.setActiveSessions(this.sessions.activeSessionCount());
        },
        onSessionClosed: async ({ ghostId, shellId, sessionId }) => {
          this.sessions.onSessionClosed({ sessionId, ghostId, shellId });
          this.offers.setActiveSessions(this.sessions.activeSessionCount());
        },
        onDAChallenged: async ({ sessionId, epoch, candidateId, challenger }) => {
          this.metrics.daChallenges += 1;
          if (!this.intervalsPerEpoch) {
            this.log.warn('DA challenge received but intervalsPerEpoch unknown; cannot respond');
            return;
          }
          try {
            await this.daResponder.respondToChallenge({ sessionId, epoch, candidateId });
          } catch (err) {
            this.log.error({ err, sessionId: sessionId.toString(), epoch: epoch.toString() }, 'DA response failed');
          }
        },
        onCandidateSubmitted: async ({ sessionId, epoch, candidateId }) => {
          this.db.raw().prepare(`UPDATE epoch_summaries SET candidate_id = ? WHERE session_id = ? AND epoch = ?`).run(candidateId, sessionId, epoch);
        },
        onReceiptFinalized: async ({ sessionId, epoch }) => {
          this.db.raw().prepare(`UPDATE epoch_summaries SET receipt_status = ? WHERE session_id = ? AND epoch = ?`).run('finalized', sessionId, epoch);
          this.db.raw().prepare(`UPDATE receipt_submissions SET finalized = 1 WHERE session_id = ? AND epoch = ?`).run(sessionId, epoch);
        },
      },
    });
  }

  async start(): Promise<void> {
    // Start heartbeat listeners.
    const t = this.cfg.network.heartbeatTransport;
    if (t === 'uds' || t === 'both') {
      await this.heartbeatUds.start();
      this.log.info({ socket: this.cfg.network.heartbeatSocketPath }, 'heartbeat UDS server started');
    }

    await this.startHttpServer();
    await this.chainListener.start();

    // Dynamic pricing tick.
    this.pricingTimer = setInterval(() => {
      void this.offers.maybeRepublishDynamic(Date.now()).catch((err) => this.log.warn({ err }, 'dynamic pricing update failed'));
    }, 10_000);

    // Epoch tick: build + submit receipts for previous epoch (best-effort).
    this.epochTimer = setInterval(() => {
      void this.tickEpoch().catch((err) => this.log.warn({ err }, 'epoch tick failed'));
    }, 30_000);
  }

  async stop(): Promise<void> {
    if (this.pricingTimer) clearInterval(this.pricingTimer);
    if (this.epochTimer) clearInterval(this.epochTimer);
    await this.chainListener.stop();
    await this.stopHttpServer();
    await this.heartbeatUds.stop();
    await this.offers.revoke().catch(() => undefined);
    this.db.close();
  }

  private async startHttpServer(): Promise<void> {
    if (this.httpServer) return;

    this.httpServer = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        if (req.method === 'GET' && url.pathname === '/healthz') {
          const shellId = this.cfg.identity.shellId ?? this.db.getMeta('shell_id');
          return writeJson(res, 200, buildHealthReport({ db: this.db, shellId, chainId: this.cfg.chain.chainId, activeSessions: this.sessions.activeSessionCount() }));
        }

        if (req.method === 'GET' && url.pathname === '/offer') {
          const bundle = this.offers.getOfferBundle();
          if (!bundle) return writeJson(res, 404, { error: 'no_offer' });
          return writeJson(res, 200, bundle);
        }

        if (req.method === 'POST' && url.pathname === '/session-key') {
          const body = await readJson(req);
          const ttlMs = typeof body.ttlMs === 'number' && Number.isFinite(body.ttlMs) ? Math.max(1_000, Math.floor(body.ttlMs)) : 5 * 60_000;

          const issued = this.sessions.issueSessionKey(ttlMs);
          const shellId = (this.cfg.identity.shellId ?? (this.db.getMeta('shell_id') as Hex | undefined)) as Hex | undefined;
          if (!shellId) return writeJson(res, 400, { error: 'shell_id_missing' });

          // Attest the public key with offer signer key.
          const offerSigner = privateKeyToAccount(this.offerSignerKey.privateKey);

          const expiresAtMs = BigInt(issued.expiresAtMs);
          const digest = tagSessionKeyDigest({ chainId: this.cfg.chain.chainId, shellId, pubkeyUncompressed: issued.publicKeyUncompressed, expiresAtMs });
          const attestationSig = (await offerSigner.sign({ hash: digest })) as Hex;

          return writeJson(res, 200, {
            sessionKey: { sigAlg: 1, pubkeyUncompressedHex: issued.publicKeyUncompressed },
            expiresAtMs: issued.expiresAtMs,
            attestationSig,
          });
        }

        if (req.method === 'POST' && url.pathname === '/heartbeat') {
          if (!(this.cfg.network.heartbeatTransport === 'http' || this.cfg.network.heartbeatTransport === 'both')) {
            return writeJson(res, 404, { error: 'heartbeat_http_disabled' });
          }
          const body = await readJson(req);
          const out = await this.heartbeat.handleHeartbeat({
            sessionId: String(body.session_id ?? body.sessionId),
            epoch: String(body.epoch),
            intervalIndex: String(body.interval_index ?? body.intervalIndex),
            sigGhost: body.sig_ghost ?? body.sigGhost,
          });
          return writeJson(res, 200, out);
        }

        writeJson(res, 404, { error: 'not_found' });
      } catch (err) {
        this.log.error({ err }, 'http handler error');
        writeJson(res, 500, { error: 'internal_error' });
      }
    });

    await new Promise<void>((resolve, reject) => {
      this.httpServer!.once('error', reject);
      this.httpServer!.listen(this.cfg.network.listenPort, this.cfg.network.listenHost, () => resolve());
    });

    this.log.info({ host: this.cfg.network.listenHost, port: this.cfg.network.listenPort }, 'http server started');
  }

  private async stopHttpServer(): Promise<void> {
    if (!this.httpServer) return;
    const s = this.httpServer;
    this.httpServer = undefined;
    await new Promise<void>((resolve, reject) => s.close((err) => (err ? reject(err) : resolve())));
  }

  private async tickEpoch(): Promise<void> {
    if (!this.intervalsPerEpoch) return;
    const nowEpoch = await this.chain.readCurrentEpoch().catch(() => undefined);
    if (nowEpoch === undefined || nowEpoch === 0n) return;

    const target = nowEpoch - 1n;
    const rows = this.db.raw().prepare(`SELECT DISTINCT session_id FROM intervals WHERE epoch = ?`).all(target) as Array<{ session_id: number | bigint }>;
    for (const r of rows) {
      const sessionId = typeof r.session_id === 'bigint' ? r.session_id : BigInt(r.session_id);
      const existing = this.db
        .raw()
        .prepare(`SELECT 1 AS ok FROM epoch_summaries WHERE session_id = ? AND epoch = ?`)
        .get(sessionId, target) as { ok: 1 } | undefined;
      if (!existing) {
        buildAndStoreReceiptTree({
          db: this.db,
          chainId: this.cfg.chain.chainId,
          sessionId,
          epoch: target,
          intervalsPerEpoch: this.intervalsPerEpoch,
        });
        this.metrics.receiptsBuilt += 1;
      }

      const submitted = this.db
        .raw()
        .prepare(`SELECT 1 AS ok FROM receipt_submissions WHERE session_id = ? AND epoch = ?`)
        .get(sessionId, target) as { ok: 1 } | undefined;
      if (!submitted) {
        await this.receiptSubmitter.submitIfWorthwhile({ sessionId, epoch: target }).catch(() => undefined);
      }
    }
  }
}
