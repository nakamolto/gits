import path from 'node:path';
import { promises as fs } from 'node:fs';

import Database from 'better-sqlite3';

export type GhostMetaRow = { key: string; value: string };

export type SessionRow = {
  session_id: number;
  ghost_id: Buffer;
  shell_id: Buffer;
  status: string;
  start_epoch: number | null;
  end_epoch: number | null;
  session_key_public: Buffer | null;
  params_json: string | null;
  migration_from_session: number | null;
  notes: string | null;
};

export type IntervalRow = {
  session_id: number;
  epoch: number;
  interval_index: number;
  vi: number;
  sig_ghost: Buffer;
  sig_shell: Buffer;
  timestamp: number;
};

export type CheckpointRow = {
  ghost_id: Buffer;
  epoch: number;
  checkpoint_commitment: Buffer;
  envelope_commitment: Buffer;
  ptr_checkpoint: string;
  ptr_envelope: string;
  created_at: number;
};

export type ShareDistributionRow = {
  ghost_id: Buffer;
  epoch: number;
  shell_id: Buffer;
  share_index: number;
  receipt_sig_shell: Buffer;
  receipt_sig_ack: Buffer;
  distributed_at: number;
};

export type ShellReputationRow = {
  shell_id: Buffer;
  total_sessions: number;
  missed_heartbeat_rate: number;
  receipt_mismatches: number;
  last_session_epoch: number;
  notes: string | null;
};

export type PolicyProposalRow = {
  proposal_id: Buffer;
  ghost_id: Buffer;
  delta_json: string;
  classification: string;
  proposed_at: number;
  executable_at: number;
  executed: number;
};

export class GhostDB {
  public readonly filePath: string;
  private readonly db: Database.Database;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.db = new Database(filePath);

    this.applyPragmas();
    this.migrate();
  }

  static async open(dataDir: string): Promise<GhostDB> {
    await fs.mkdir(dataDir, { recursive: true });
    return new GhostDB(path.join(dataDir, 'ghost.db'));
  }

  close(): void {
    this.db.close();
  }

  getJournalMode(): string {
    return this.db.pragma('journal_mode', { simple: true }) as string;
  }

  private applyPragmas(): void {
    // Crash safety + concurrent readers.
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000');
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ghost_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        session_id INTEGER PRIMARY KEY,
        ghost_id BLOB NOT NULL,
        shell_id BLOB NOT NULL,
        status TEXT NOT NULL,
        start_epoch INT,
        end_epoch INT,
        session_key_public BLOB,
        params_json TEXT,
        migration_from_session INT,
        notes TEXT
      );

      CREATE TABLE IF NOT EXISTS intervals (
        session_id INT NOT NULL,
        epoch INT NOT NULL,
        interval_index INT NOT NULL,
        vi INT NOT NULL,
        sig_ghost BLOB NOT NULL,
        sig_shell BLOB NOT NULL,
        timestamp INT NOT NULL,
        PRIMARY KEY (session_id, epoch, interval_index)
      );

      CREATE TABLE IF NOT EXISTS checkpoints (
        ghost_id BLOB NOT NULL,
        epoch INT NOT NULL,
        checkpoint_commitment BLOB NOT NULL,
        envelope_commitment BLOB NOT NULL,
        ptr_checkpoint TEXT NOT NULL,
        ptr_envelope TEXT NOT NULL,
        created_at INT NOT NULL,
        PRIMARY KEY (ghost_id, epoch)
      );

      CREATE TABLE IF NOT EXISTS share_distributions (
        ghost_id BLOB NOT NULL,
        epoch INT NOT NULL,
        shell_id BLOB NOT NULL,
        share_index INT NOT NULL,
        receipt_sig_shell BLOB NOT NULL,
        receipt_sig_ack BLOB NOT NULL,
        distributed_at INT NOT NULL,
        PRIMARY KEY (ghost_id, epoch, shell_id)
      );

      CREATE TABLE IF NOT EXISTS shell_reputation (
        shell_id BLOB PRIMARY KEY,
        total_sessions INT NOT NULL,
        missed_heartbeat_rate REAL NOT NULL,
        receipt_mismatches INT NOT NULL,
        last_session_epoch INT NOT NULL,
        notes TEXT
      );

      CREATE TABLE IF NOT EXISTS policy_proposals (
        proposal_id BLOB PRIMARY KEY,
        ghost_id BLOB NOT NULL,
        delta_json TEXT NOT NULL,
        classification TEXT NOT NULL,
        proposed_at INT NOT NULL,
        executable_at INT NOT NULL,
        executed INT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS spend_tracking (
        ghost_id BLOB NOT NULL,
        epoch INTEGER NOT NULL,
        spent_amount TEXT NOT NULL,
        PRIMARY KEY (ghost_id, epoch)
      );

      CREATE TABLE IF NOT EXISTS chain_cursor (
        id INT PRIMARY KEY DEFAULT 1,
        last_block INT NOT NULL
      );

      INSERT INTO chain_cursor (id, last_block) VALUES (1, 0)
      ON CONFLICT(id) DO NOTHING;

      CREATE INDEX IF NOT EXISTS idx_sessions_ghost_id ON sessions(ghost_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_shell_id ON sessions(shell_id);
      CREATE INDEX IF NOT EXISTS idx_intervals_epoch ON intervals(epoch);
      CREATE INDEX IF NOT EXISTS idx_checkpoints_epoch ON checkpoints(epoch);
      CREATE INDEX IF NOT EXISTS idx_policy_proposals_executable ON policy_proposals(executable_at);
    `);
  }

  // ─── ghost_meta ─────────────────────────────────────────────────────────

  getMeta(key: string): string | undefined {
    const row = this.db.prepare('SELECT value FROM ghost_meta WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value;
  }

  setMeta(key: string, value: string): void {
    this.db.prepare('INSERT INTO ghost_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(
      key,
      value,
    );
  }

  // ─── spend_tracking ─────────────────────────────────────────────────────

  getSpentThisEpoch(ghostId: Uint8Array, epoch: number): bigint {
    const row = this.db
      .prepare('SELECT spent_amount FROM spend_tracking WHERE ghost_id = ? AND epoch = ?')
      .get(Buffer.from(ghostId), epoch) as { spent_amount: string } | undefined;
    return row ? BigInt(row.spent_amount) : 0n;
  }

  setSpentThisEpoch(ghostId: Uint8Array, epoch: number, amount: bigint): void {
    this.db
      .prepare(
        `INSERT INTO spend_tracking(ghost_id, epoch, spent_amount) VALUES(?, ?, ?)
         ON CONFLICT(ghost_id, epoch) DO UPDATE SET spent_amount = excluded.spent_amount`,
      )
      .run(Buffer.from(ghostId), epoch, amount.toString());
  }

  // ─── sessions ───────────────────────────────────────────────────────────

  insertSession(row: {
    session_id: number;
    ghost_id: Uint8Array;
    shell_id: Uint8Array;
    status: string;
    start_epoch?: number | null;
    end_epoch?: number | null;
    session_key_public?: Uint8Array | null;
    params_json?: string | null;
    migration_from_session?: number | null;
    notes?: string | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO sessions(
          session_id, ghost_id, shell_id, status, start_epoch, end_epoch, session_key_public, params_json, migration_from_session, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.session_id,
        Buffer.from(row.ghost_id),
        Buffer.from(row.shell_id),
        row.status,
        row.start_epoch ?? null,
        row.end_epoch ?? null,
        row.session_key_public != null ? Buffer.from(row.session_key_public) : null,
        row.params_json ?? null,
        row.migration_from_session ?? null,
        row.notes ?? null,
      );
  }

  updateSessionStatus(session_id: number, status: string, end_epoch?: number | null, notes?: string | null): void {
    this.db
      .prepare('UPDATE sessions SET status = ?, end_epoch = COALESCE(?, end_epoch), notes = COALESCE(?, notes) WHERE session_id = ?')
      .run(status, end_epoch ?? null, notes ?? null, session_id);
  }

  getSession(session_id: number): SessionRow | undefined {
    return this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(session_id) as SessionRow | undefined;
  }

  listSessions(): SessionRow[] {
    return this.db.prepare('SELECT * FROM sessions ORDER BY session_id DESC').all() as SessionRow[];
  }

  // ─── intervals ──────────────────────────────────────────────────────────

  insertInterval(row: {
    session_id: number;
    epoch: number;
    interval_index: number;
    vi: number;
    sig_ghost: Uint8Array;
    sig_shell: Uint8Array;
    timestamp: number;
  }): void {
    this.db
      .prepare(
        'INSERT INTO intervals(session_id, epoch, interval_index, vi, sig_ghost, sig_shell, timestamp) VALUES(?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        row.session_id,
        row.epoch,
        row.interval_index,
        row.vi,
        Buffer.from(row.sig_ghost),
        Buffer.from(row.sig_shell),
        row.timestamp,
      );
  }

  getIntervals(session_id: number, epoch: number): IntervalRow[] {
    return this.db
      .prepare('SELECT * FROM intervals WHERE session_id = ? AND epoch = ? ORDER BY interval_index ASC')
      .all(session_id, epoch) as IntervalRow[];
  }

  // ─── checkpoints ────────────────────────────────────────────────────────

  insertCheckpoint(row: {
    ghost_id: Uint8Array;
    epoch: number;
    checkpoint_commitment: Uint8Array;
    envelope_commitment: Uint8Array;
    ptr_checkpoint: string;
    ptr_envelope: string;
    created_at: number;
  }): void {
    this.db
      .prepare(
        'INSERT INTO checkpoints(ghost_id, epoch, checkpoint_commitment, envelope_commitment, ptr_checkpoint, ptr_envelope, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        Buffer.from(row.ghost_id),
        row.epoch,
        Buffer.from(row.checkpoint_commitment),
        Buffer.from(row.envelope_commitment),
        row.ptr_checkpoint,
        row.ptr_envelope,
        row.created_at,
      );
  }

  getCheckpoint(ghost_id: Uint8Array, epoch: number): CheckpointRow | undefined {
    return this.db
      .prepare('SELECT * FROM checkpoints WHERE ghost_id = ? AND epoch = ?')
      .get(Buffer.from(ghost_id), epoch) as CheckpointRow | undefined;
  }

  getLatestCheckpoint(ghost_id: Uint8Array): CheckpointRow | undefined {
    return this.db
      .prepare('SELECT * FROM checkpoints WHERE ghost_id = ? ORDER BY epoch DESC LIMIT 1')
      .get(Buffer.from(ghost_id)) as CheckpointRow | undefined;
  }

  // ─── share_distributions ────────────────────────────────────────────────

  insertShareDistribution(row: {
    ghost_id: Uint8Array;
    epoch: number;
    shell_id: Uint8Array;
    share_index: number;
    receipt_sig_shell: Uint8Array;
    receipt_sig_ack: Uint8Array;
    distributed_at: number;
  }): void {
    this.db
      .prepare(
        'INSERT INTO share_distributions(ghost_id, epoch, shell_id, share_index, receipt_sig_shell, receipt_sig_ack, distributed_at) VALUES(?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        Buffer.from(row.ghost_id),
        row.epoch,
        Buffer.from(row.shell_id),
        row.share_index,
        Buffer.from(row.receipt_sig_shell),
        Buffer.from(row.receipt_sig_ack),
        row.distributed_at,
      );
  }

  getShareDistributions(ghost_id: Uint8Array, epoch: number): ShareDistributionRow[] {
    return this.db
      .prepare('SELECT * FROM share_distributions WHERE ghost_id = ? AND epoch = ?')
      .all(Buffer.from(ghost_id), epoch) as ShareDistributionRow[];
  }

  // ─── shell_reputation ───────────────────────────────────────────────────

  upsertShellReputation(row: {
    shell_id: Uint8Array;
    total_sessions: number;
    missed_heartbeat_rate: number;
    receipt_mismatches: number;
    last_session_epoch: number;
    notes?: string | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO shell_reputation(shell_id, total_sessions, missed_heartbeat_rate, receipt_mismatches, last_session_epoch, notes)
         VALUES(?, ?, ?, ?, ?, ?)
         ON CONFLICT(shell_id) DO UPDATE SET
          total_sessions=excluded.total_sessions,
          missed_heartbeat_rate=excluded.missed_heartbeat_rate,
          receipt_mismatches=excluded.receipt_mismatches,
          last_session_epoch=excluded.last_session_epoch,
          notes=excluded.notes`,
      )
      .run(
        Buffer.from(row.shell_id),
        row.total_sessions,
        row.missed_heartbeat_rate,
        row.receipt_mismatches,
        row.last_session_epoch,
        row.notes ?? null,
      );
  }

  getShellReputation(shell_id: Uint8Array): ShellReputationRow | undefined {
    return this.db
      .prepare('SELECT * FROM shell_reputation WHERE shell_id = ?')
      .get(Buffer.from(shell_id)) as ShellReputationRow | undefined;
  }

  // ─── policy_proposals ───────────────────────────────────────────────────

  insertPolicyProposal(row: {
    proposal_id: Uint8Array;
    ghost_id: Uint8Array;
    delta_json: string;
    classification: string;
    proposed_at: number;
    executable_at: number;
    executed?: number;
  }): void {
    this.db
      .prepare(
        'INSERT INTO policy_proposals(proposal_id, ghost_id, delta_json, classification, proposed_at, executable_at, executed) VALUES(?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        Buffer.from(row.proposal_id),
        Buffer.from(row.ghost_id),
        row.delta_json,
        row.classification,
        row.proposed_at,
        row.executable_at,
        row.executed ?? 0,
      );
  }

  markPolicyExecuted(proposal_id: Uint8Array): void {
    this.db
      .prepare('UPDATE policy_proposals SET executed = 1 WHERE proposal_id = ?')
      .run(Buffer.from(proposal_id));
  }

  getPendingPolicyProposals(now: number): PolicyProposalRow[] {
    return this.db
      .prepare('SELECT * FROM policy_proposals WHERE executed = 0 AND executable_at <= ? ORDER BY executable_at ASC')
      .all(now) as PolicyProposalRow[];
  }

  // ─── chain_cursor ───────────────────────────────────────────────────────

  getChainCursor(): number {
    const row = this.db.prepare('SELECT last_block FROM chain_cursor WHERE id = 1').get() as { last_block: number };
    return row?.last_block ?? 0;
  }

  setChainCursor(last_block: number): void {
    this.db.prepare('UPDATE chain_cursor SET last_block = ? WHERE id = 1').run(last_block);
  }
}
