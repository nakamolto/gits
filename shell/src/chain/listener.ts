import { decodeFunctionData, parseAbi, parseAbiItem } from 'viem';
import type { Address, Hex } from 'viem';

import type { ShellConfig } from '../config/config.js';
import type { ShellDb } from '../storage/db.js';
import { ABIS } from './submitter.js';

const OPEN_SESSION_ABI = parseAbi([
  'function openSession(bytes32 ghost_id, bytes32 shell_id, (uint256 price_per_SU, uint32 max_SU, uint256 lease_expiry_epoch, uint256 tenure_limit_epochs, bytes ghost_session_key, bytes shell_session_key, address submitter_address, address asset) params) external',
]);

const EVT_SESSION_OPENED = parseAbiItem('event SessionOpened(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)');
const EVT_SESSION_CLOSED = parseAbiItem('event SessionClosed(bytes32 indexed ghost_id, bytes32 indexed shell_id, uint256 session_id)');

const EVT_DA_CHALLENGED = parseAbiItem('event DAChallenged(uint256 indexed session_id, uint256 indexed epoch, uint256 candidate_id, address challenger)');
const EVT_CANDIDATE_SUBMITTED = parseAbiItem('event CandidateSubmitted(uint256 indexed session_id, uint256 indexed epoch, uint256 candidate_id, address submitter, uint32 su_delivered)');
const EVT_RECEIPT_FINALIZED = parseAbiItem(
  'event ReceiptFinalized(uint256 indexed session_id, uint256 indexed epoch, bytes32 receipt_id, uint32 su_delivered, address submitter, uint256 weight_q)',
);

type ListenerLog =
  | { event: 'SessionOpened'; blockNumber: bigint; logIndex: number; txHash: Hex; args: { ghost_id: Hex; shell_id: Hex; session_id: bigint } }
  | { event: 'SessionClosed'; blockNumber: bigint; logIndex: number; txHash: Hex; args: { ghost_id: Hex; shell_id: Hex; session_id: bigint } }
  | { event: 'DAChallenged'; blockNumber: bigint; logIndex: number; txHash: Hex; args: { session_id: bigint; epoch: bigint; candidate_id: bigint; challenger: Address } }
  | {
      event: 'CandidateSubmitted';
      blockNumber: bigint;
      logIndex: number;
      txHash: Hex;
      args: { session_id: bigint; epoch: bigint; candidate_id: bigint; submitter: Address; su_delivered: number };
    }
  | {
      event: 'ReceiptFinalized';
      blockNumber: bigint;
      logIndex: number;
      txHash: Hex;
      args: { session_id: bigint; epoch: bigint; receipt_id: Hex; su_delivered: number; submitter: Address; weight_q: bigint };
    };

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export interface ChainListenerHandlers {
  onSessionOpened(args: {
    ghostId: Hex;
    shellId: Hex;
    sessionId: bigint;
    txHash: Hex;
    paramsJson?: string;
  }): Promise<void> | void;
  onSessionClosed(args: { ghostId: Hex; shellId: Hex; sessionId: bigint; txHash: Hex }): Promise<void> | void;
  onDAChallenged(args: { sessionId: bigint; epoch: bigint; candidateId: bigint; challenger: Address; txHash: Hex }): Promise<void> | void;
  onCandidateSubmitted(args: {
    sessionId: bigint;
    epoch: bigint;
    candidateId: bigint;
    submitter: Address;
    suDelivered: number;
    txHash: Hex;
  }): Promise<void> | void;
  onReceiptFinalized(args: { sessionId: bigint; epoch: bigint; suDelivered: number; txHash: Hex }): Promise<void> | void;
}

export class ChainListener {
  private readonly cfg: ShellConfig;
  private readonly db: ShellDb;
  private readonly publicClient: any;
  private readonly handlers: ChainListenerHandlers;
  private readonly log: any;

  private running = false;
  private pollIntervalMs = 5_000;
  private loopPromise: Promise<void> | null = null;

  constructor(args: { cfg: ShellConfig; db: ShellDb; publicClient: any; handlers: ChainListenerHandlers; logger?: any }) {
    this.cfg = args.cfg;
    this.db = args.db;
    this.publicClient = args.publicClient;
    this.handlers = args.handlers;
    this.log = args.logger ?? console;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.loopPromise = this.loop();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.loopPromise) {
      await this.loopPromise;
      this.loopPromise = null;
    }
  }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        await this.tick();
      } catch (err) {
        this.log.error({ err }, 'chain listener tick failed');
      }
      await sleep(this.pollIntervalMs);
    }
  }

  private async tick(): Promise<void> {
    const latest = (await this.publicClient.getBlockNumber()) as bigint;
    let last = this.db.getChainCursor();
    if (last === undefined) {
      // v1 default: start at head (no backfill) unless operator sets cursor manually.
      this.db.setChainCursor(latest);
      return;
    }
    if (latest <= last) return;

    const CHUNK = 2_000n;
    let from = last + 1n;
    while (from <= latest) {
      const to = from + CHUNK - 1n <= latest ? from + CHUNK - 1n : latest;
      const ok = await this.processRange(from, to);
      if (!ok) return; // don't advance cursor; retry later
      this.db.setChainCursor(to);
      last = to;
      from = to + 1n;
    }
  }

  private async processRange(fromBlock: bigint, toBlock: bigint): Promise<boolean> {
    const sessionMgr = this.cfg.chain.deployment.sessionManager;
    const receiptMgr = this.cfg.chain.deployment.receiptManager;

    const [opened, closed, da, submitted, finalized] = await Promise.all([
      this.publicClient.getLogs({ address: sessionMgr, event: EVT_SESSION_OPENED, fromBlock, toBlock }),
      this.publicClient.getLogs({ address: sessionMgr, event: EVT_SESSION_CLOSED, fromBlock, toBlock }),
      this.publicClient.getLogs({ address: receiptMgr, event: EVT_DA_CHALLENGED, fromBlock, toBlock }),
      this.publicClient.getLogs({ address: receiptMgr, event: EVT_CANDIDATE_SUBMITTED, fromBlock, toBlock }),
      this.publicClient.getLogs({ address: receiptMgr, event: EVT_RECEIPT_FINALIZED, fromBlock, toBlock }),
    ]);

    const logs: ListenerLog[] = [];
    for (const l of opened) {
      logs.push({
        event: 'SessionOpened',
        blockNumber: l.blockNumber,
        logIndex: Number(l.logIndex),
        txHash: l.transactionHash,
        args: l.args,
      });
    }
    for (const l of closed) {
      logs.push({
        event: 'SessionClosed',
        blockNumber: l.blockNumber,
        logIndex: Number(l.logIndex),
        txHash: l.transactionHash,
        args: l.args,
      });
    }
    for (const l of da) {
      logs.push({
        event: 'DAChallenged',
        blockNumber: l.blockNumber,
        logIndex: Number(l.logIndex),
        txHash: l.transactionHash,
        args: l.args,
      });
    }
    for (const l of submitted) {
      logs.push({
        event: 'CandidateSubmitted',
        blockNumber: l.blockNumber,
        logIndex: Number(l.logIndex),
        txHash: l.transactionHash,
        args: l.args,
      });
    }
    for (const l of finalized) {
      logs.push({
        event: 'ReceiptFinalized',
        blockNumber: l.blockNumber,
        logIndex: Number(l.logIndex),
        txHash: l.transactionHash,
        args: l.args,
      });
    }

    logs.sort((a, b) => {
      if (a.blockNumber !== b.blockNumber) return a.blockNumber < b.blockNumber ? -1 : 1;
      return a.logIndex - b.logIndex;
    });

    for (const log of logs) {
      try {
        if (log.event === 'SessionOpened') {
          const paramsJson = await this.tryDecodeOpenSessionParams(log.txHash);
          await this.handlers.onSessionOpened({
            ghostId: log.args.ghost_id,
            shellId: log.args.shell_id,
            sessionId: log.args.session_id,
            txHash: log.txHash,
            paramsJson,
          });
        } else if (log.event === 'SessionClosed') {
          await this.handlers.onSessionClosed({
            ghostId: log.args.ghost_id,
            shellId: log.args.shell_id,
            sessionId: log.args.session_id,
            txHash: log.txHash,
          });
        } else if (log.event === 'DAChallenged') {
          await this.handlers.onDAChallenged({
            sessionId: log.args.session_id,
            epoch: log.args.epoch,
            candidateId: log.args.candidate_id,
            challenger: log.args.challenger,
            txHash: log.txHash,
          });
        } else if (log.event === 'CandidateSubmitted') {
          await this.handlers.onCandidateSubmitted({
            sessionId: log.args.session_id,
            epoch: log.args.epoch,
            candidateId: log.args.candidate_id,
            submitter: log.args.submitter,
            suDelivered: Number(log.args.su_delivered),
            txHash: log.txHash,
          });
        } else if (log.event === 'ReceiptFinalized') {
          await this.handlers.onReceiptFinalized({
            sessionId: log.args.session_id,
            epoch: log.args.epoch,
            suDelivered: Number(log.args.su_delivered),
            txHash: log.txHash,
          });
        }
      } catch (err) {
        this.log.error({ err, event: log.event, txHash: log.txHash }, 'failed to process log');
        return false;
      }
    }

    return true;
  }

  private async tryDecodeOpenSessionParams(txHash: Hex): Promise<string | undefined> {
    try {
      const tx = await this.publicClient.getTransaction({ hash: txHash });
      if (!tx || !tx.input) return undefined;
      const decoded = decodeFunctionData({ abi: OPEN_SESSION_ABI, data: tx.input });
      if (decoded.functionName !== 'openSession') return undefined;
      const [, , params] = decoded.args as any[];
      return JSON.stringify(params);
    } catch {
      return undefined;
    }
  }
}
