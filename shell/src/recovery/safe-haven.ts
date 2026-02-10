import type { AuthSig, RBC, ShareReceipt } from '@gits-protocol/sdk';
import { recoverAuthDigest, shareAckDigest, shareDigest } from '@gits-protocol/sdk';

import type { Hex } from 'viem';
import { toHex } from 'viem';
import type { LocalAccount } from 'viem/accounts';

import type { ShellDb, SqliteDatabase } from '../storage/db.js';

export type LocalSignerAccount = LocalAccount & { sign: NonNullable<LocalAccount['sign']> };

export interface ShamirShareStore {
  receiveShare(ghost_id: Hex, share_index: number, encrypted_share: Uint8Array, received_epoch: number): void;
  getShares(
    ghost_id: Hex,
  ): Array<{ share_index: number; encrypted_share: Uint8Array; received_epoch: number }>;
  purgeShares(ghost_id: Hex): void;
}

export interface RecoveryAttemptProvider {
  getRecoveryAttempt(
    ghost_id: Hex,
    attempt_id: bigint,
  ): Promise<{ checkpoint_commitment: Hex; envelope_commitment: Hex }>;
}

export interface SessionManagerLike {
  startRecovery(ghost_id: Hex): Promise<bigint>;
  recoveryRotate(
    ghost_id: Hex,
    attempt_id: bigint,
    new_identity_pubkey: Hex,
    rbc: RBC,
    rs_list: Hex[],
    sigs: AuthSig[],
    share_receipts: ShareReceipt[],
  ): Promise<void>;
  isActiveRecoveryInitiator(shell_id: Hex): Promise<boolean>;
}

export type DecryptShareFn = (encrypted: Uint8Array) => Promise<Uint8Array>;

export type AuthorizeRequest = {
  chain_id: bigint;
  ghost_id: Hex;
  attempt_id: bigint;
  checkpoint_commitment: Hex;
  pk_new: Hex;
  rbc: RBC;
};

export type AuthorizeResponse = {
  auth_sig: AuthSig;
  share_receipt: ShareReceipt;
  decrypted_share: { share_index: number; share: Hex };
};

export class SafeHavenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class NoShareError extends SafeHavenError {
  constructor(ghost_id: Hex) {
    super(`No Shamir shares stored for ghost_id=${ghost_id}`);
  }
}

export class CheckpointMismatchError extends SafeHavenError {
  constructor(expected: Hex, actual: Hex) {
    super(`checkpoint_commitment mismatch (expected=${expected}, actual=${actual})`);
  }
}

export class RBCMismatchError extends SafeHavenError {
  constructor(field: string) {
    super(`RBC mismatch for field: ${field}`);
  }
}

export class ShareDecryptError extends SafeHavenError {
  public readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

export class ActiveRecoveryInitiatorError extends SafeHavenError {
  constructor(shell_id: Hex) {
    super(`Shell is an active recovery initiator; refusing to unbond (shell_id=${shell_id})`);
  }
}

export class ThresholdNotMetError extends SafeHavenError {
  constructor(threshold: number, received: number) {
    super(`Recovery authorization threshold not met (threshold=${threshold}, received=${received})`);
  }
}

export class ChainIdMismatchError extends SafeHavenError {
  constructor(expected: bigint, actual: bigint) {
    super(`chain_id mismatch (expected=${expected}, actual=${actual})`);
  }
}

function hexToBytesStrict(hex: Hex): Uint8Array {
  if (!hex.startsWith('0x')) throw new Error(`Invalid hex: ${hex}`);
  const body = hex.slice(2);
  if (body.length % 2 !== 0) throw new Error(`Invalid hex length: ${hex}`);
  return Uint8Array.from(Buffer.from(body, 'hex'));
}

function bytesToHexStrict(bytes: Uint8Array): Hex {
  return toHex(bytes) as Hex;
}

type PreparedStatement = ReturnType<SqliteDatabase['prepare']>;

export class SqliteShamirShareStore implements ShamirShareStore {
  private readonly insertStmt: PreparedStatement;
  private readonly selectStmt: PreparedStatement;
  private readonly purgeStmt: PreparedStatement;

  constructor(db: ShellDb) {
    const raw = db.raw();
    // Table created by ShellDb migration.
    this.insertStmt = raw.prepare(
      `INSERT OR REPLACE INTO shamir_shares (ghost_id, share_index, encrypted_share, received_epoch) VALUES (?, ?, ?, ?)`,
    );
    this.selectStmt = raw.prepare(
      `SELECT share_index, encrypted_share, received_epoch FROM shamir_shares WHERE ghost_id = ? ORDER BY share_index ASC`,
    );
    this.purgeStmt = raw.prepare(`DELETE FROM shamir_shares WHERE ghost_id = ?`);
  }

  receiveShare(ghost_id: Hex, share_index: number, encrypted_share: Uint8Array, received_epoch: number): void {
    const ghostBytes = Buffer.from(hexToBytesStrict(ghost_id));
    const shareBytes = Buffer.from(encrypted_share);

    // better-sqlite3 expects variadic params (not a single array param).
    this.insertStmt.run(ghostBytes, share_index, shareBytes, received_epoch);
  }

  getShares(ghost_id: Hex): Array<{ share_index: number; encrypted_share: Uint8Array; received_epoch: number }> {
    const ghostBytes = Buffer.from(hexToBytesStrict(ghost_id));
    const rows = this.selectStmt.all(ghostBytes) as Array<{
      share_index: number;
      encrypted_share: Uint8Array | Buffer | number[];
      received_epoch: number;
    }>;

    return rows.map((r) => ({
      share_index: Number(r.share_index),
      encrypted_share: Uint8Array.from(r.encrypted_share as any),
      received_epoch: Number(r.received_epoch),
    }));
  }

  purgeShares(ghost_id: Hex): void {
    const ghostBytes = Buffer.from(hexToBytesStrict(ghost_id));
    this.purgeStmt.run(ghostBytes);
  }
}

export class SafeHaven {
  constructor(
    public readonly opts: {
      chain_id: bigint;
      shell_id: Hex;
      identity_account: LocalSignerAccount;
      recovery_account: LocalSignerAccount;
      store: ShamirShareStore;
      attempts: RecoveryAttemptProvider;
      decryptShare: DecryptShareFn;
    },
  ) {}

  receiveShare(ghost_id: Hex, share_index: number, encrypted_share: Uint8Array, received_epoch: number): void {
    this.opts.store.receiveShare(ghost_id, share_index, encrypted_share, received_epoch);
  }

  getShares(ghost_id: Hex): Array<{ share_index: number; encrypted_share: Uint8Array; received_epoch: number }> {
    return this.opts.store.getShares(ghost_id);
  }

  purgeShares(ghost_id: Hex): void {
    this.opts.store.purgeShares(ghost_id);
  }

  async authorizeRecovery(req: AuthorizeRequest): Promise<AuthorizeResponse> {
    if (req.chain_id !== this.opts.chain_id) throw new ChainIdMismatchError(this.opts.chain_id, req.chain_id);
    if (req.rbc.ghost_id !== req.ghost_id) throw new RBCMismatchError('ghost_id');
    if (req.rbc.attempt_id !== req.attempt_id) throw new RBCMismatchError('attempt_id');
    if (req.rbc.checkpoint_commitment !== req.checkpoint_commitment) throw new RBCMismatchError('checkpoint_commitment');
    if (req.rbc.pk_new !== req.pk_new) throw new RBCMismatchError('pk_new');

    const attempt = await this.opts.attempts.getRecoveryAttempt(req.ghost_id, req.attempt_id);
    if (attempt.checkpoint_commitment !== req.checkpoint_commitment) {
      throw new CheckpointMismatchError(req.checkpoint_commitment, attempt.checkpoint_commitment);
    }

    const shares = this.opts.store.getShares(req.ghost_id);
    if (shares.length === 0) throw new NoShareError(req.ghost_id);
    const shareRow = shares[0];

    let decrypted: Uint8Array;
    try {
      decrypted = await this.opts.decryptShare(shareRow.encrypted_share);
    } catch (err) {
      throw new ShareDecryptError('Failed to decrypt Shamir share', err);
    }

    const authHash = recoverAuthDigest({
      chain_id: this.opts.chain_id,
      ghost_id: req.ghost_id,
      attempt_id: req.attempt_id,
      checkpoint_commitment: req.checkpoint_commitment,
      pk_new: req.pk_new,
    });
    const sigAuth = await this.opts.identity_account.sign({ hash: authHash });

    const shareHash = shareDigest({
      chain_id: this.opts.chain_id,
      ghost_id: req.ghost_id,
      attempt_id: req.attempt_id,
      checkpoint_commitment: req.checkpoint_commitment,
      envelope_commitment: attempt.envelope_commitment,
    });
    const sigShell = await this.opts.identity_account.sign({ hash: shareHash });

    const ackHash = shareAckDigest({
      chain_id: this.opts.chain_id,
      ghost_id: req.ghost_id,
      attempt_id: req.attempt_id,
      checkpoint_commitment: req.checkpoint_commitment,
      envelope_commitment: attempt.envelope_commitment,
    });
    const sigAck = await this.opts.recovery_account.sign({ hash: ackHash });

    return {
      auth_sig: { shell_id: this.opts.shell_id, signature: sigAuth },
      share_receipt: { shell_id: this.opts.shell_id, sig_shell: sigShell, sig_ack: sigAck },
      decrypted_share: { share_index: shareRow.share_index, share: bytesToHexStrict(decrypted) },
    };
  }

  async initiateRecovery(args: {
    ghost_id: Hex;
    checkpoint_commitment: Hex;
    pk_new: Hex;
    rbc: RBC;
    rs_list: Hex[];
    threshold: number;
    session_manager: SessionManagerLike;
    requestAuth: (shell_id: Hex, req: AuthorizeRequest) => Promise<AuthorizeResponse>;
  }): Promise<{ attempt_id: bigint; sigs: AuthSig[]; share_receipts: ShareReceipt[] }> {
    const attempt_id = await args.session_manager.startRecovery(args.ghost_id);

    const rbc: RBC = {
      ...args.rbc,
      ghost_id: args.ghost_id,
      attempt_id,
      checkpoint_commitment: args.checkpoint_commitment,
      pk_new: args.pk_new,
    };

    const sigs: AuthSig[] = [];
    const share_receipts: ShareReceipt[] = [];

    for (const member of args.rs_list) {
      if (sigs.length >= args.threshold) break;

      try {
        const resp = await args.requestAuth(member, {
          chain_id: this.opts.chain_id,
          ghost_id: args.ghost_id,
          attempt_id,
          checkpoint_commitment: args.checkpoint_commitment,
          pk_new: args.pk_new,
          rbc,
        });
        sigs.push(resp.auth_sig);
        share_receipts.push(resp.share_receipt);
      } catch {
        // Best-effort collection; continue to next member.
      }
    }

    if (sigs.length < args.threshold) throw new ThresholdNotMetError(args.threshold, sigs.length);

    await args.session_manager.recoveryRotate(
      args.ghost_id,
      attempt_id,
      args.pk_new,
      rbc,
      args.rs_list,
      sigs,
      share_receipts,
    );

    return { attempt_id, sigs, share_receipts };
  }

  async assertCanUnbondSafeHaven(session_manager: SessionManagerLike): Promise<void> {
    const active = await session_manager.isActiveRecoveryInitiator(this.opts.shell_id);
    if (active) throw new ActiveRecoveryInitiatorError(this.opts.shell_id);
  }
}

export function createAuthorizeHandler(sh: SafeHaven): (body: AuthorizeRequest) => Promise<AuthorizeResponse> {
  return async (body) => sh.authorizeRecovery(body);
}
