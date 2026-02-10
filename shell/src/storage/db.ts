import fs from 'node:fs/promises';
import path from 'node:path';

import Database from 'better-sqlite3';

export type SqliteDatabase = Database.Database;

export interface ShellDbOptions {
  filename: string;
  readonly?: boolean;
}

export class ShellDb {
  public readonly filename: string;
  private readonly db: SqliteDatabase;

  constructor(opts: ShellDbOptions) {
    this.filename = opts.filename;
    this.db = new Database(opts.filename, { readonly: opts.readonly ?? false });
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  static async openAtDataDir(dataDir: string): Promise<ShellDb> {
    await fs.mkdir(dataDir, { recursive: true });
    const filename = path.join(dataDir, 'shell.db');
    return new ShellDb({ filename });
  }

  close(): void {
    this.db.close();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS shell_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        session_id INTEGER PRIMARY KEY,
        ghost_id BLOB NOT NULL,
        shell_id BLOB NOT NULL,
        status TEXT NOT NULL,
        start_epoch INTEGER NOT NULL,
        end_epoch INTEGER,
        session_key_public BLOB,
        params_json TEXT
      );

      CREATE TABLE IF NOT EXISTS intervals (
        session_id INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        interval_index INTEGER NOT NULL,
        vi INTEGER NOT NULL,
        sig_ghost BLOB,
        sig_shell BLOB,
        timestamp INTEGER NOT NULL,
        PRIMARY KEY (session_id, epoch, interval_index)
      );

      CREATE INDEX IF NOT EXISTS idx_intervals_session_epoch ON intervals(session_id, epoch);

      CREATE TABLE IF NOT EXISTS epoch_summaries (
        session_id INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        log_root BLOB NOT NULL,
        su_delivered INTEGER NOT NULL,
        candidate_id INTEGER,
        receipt_status TEXT,
        PRIMARY KEY (session_id, epoch)
      );

      CREATE TABLE IF NOT EXISTS receipt_submissions (
        session_id INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        candidate_id INTEGER NOT NULL,
        tx_hash BLOB,
        submitted_at INTEGER NOT NULL,
        finalized INTEGER NOT NULL,
        PRIMARY KEY (session_id, epoch)
      );

      CREATE TABLE IF NOT EXISTS chain_cursor (
        id INTEGER PRIMARY KEY DEFAULT 1,
        last_block INTEGER NOT NULL
      );
    `);
  }

  getMeta(key: string): string | undefined {
    const row = this.db.prepare(`SELECT value FROM shell_meta WHERE key = ?`).get(key) as { value: string } | undefined;
    return row?.value;
  }

  setMeta(key: string, value: string): void {
    this.db
      .prepare(`INSERT INTO shell_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
      .run(key, value);
  }

  getChainCursor(): bigint | undefined {
    const row = this.db.prepare(`SELECT last_block FROM chain_cursor WHERE id = 1`).get() as { last_block: number | bigint } | undefined;
    if (!row) return undefined;
    return typeof row.last_block === 'bigint' ? row.last_block : BigInt(row.last_block);
  }

  setChainCursor(lastBlock: bigint): void {
    this.db
      .prepare(`INSERT INTO chain_cursor(id, last_block) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET last_block = excluded.last_block`)
      .run(lastBlock);
  }

  // Expose underlying db for prepared statement reuse in helper modules.
  raw(): SqliteDatabase {
    return this.db;
  }
}

