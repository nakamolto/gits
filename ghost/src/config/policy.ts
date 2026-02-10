import Database from 'better-sqlite3';

import type { Hex } from 'viem';

import type { Policy, PolicyDelta } from '../../../sdk/src/types/structs.js';

export type ProposalStatus = 'pending' | 'executed' | 'cancelled';

export interface PolicyProposalRow {
  proposal_id: Hex;
  ghost_id: Hex;
  delta: PolicyDelta;
  created_at_ms: number;
  executable_at_ms: number;
  status: ProposalStatus;
}

export interface GhostWalletPolicyReader {
  getPolicy(ghostId: Hex): Promise<Policy>;
}

const BIGINT_DELTA_FIELDS: Array<keyof PolicyDelta> = [
  'hot_allowance_delta',
  'escape_gas_delta',
  'escape_stable_delta',
  'new_t_guardian',
];

export function serializePolicyDelta(delta: PolicyDelta): string {
  return JSON.stringify(delta, (_k, v) => (typeof v === 'bigint' ? v.toString(10) : v));
}

export function deserializePolicyDelta(deltaJson: string): PolicyDelta {
  const obj = JSON.parse(deltaJson) as Record<string, unknown>;

  for (const key of BIGINT_DELTA_FIELDS) {
    const v = obj[key as string];
    if (typeof v !== 'string') throw new TypeError(`Invalid PolicyDelta JSON: expected string for ${String(key)}`);
    obj[key as string] = BigInt(v);
  }

  return obj as unknown as PolicyDelta;
}

export class LocalPolicyState {
  private readonly wallet: GhostWalletPolicyReader;
  private readonly db: Database.Database;
  private readonly policyCache = new Map<Hex, Policy>();

  constructor(opts: { wallet: GhostWalletPolicyReader; sqlitePath?: string }) {
    this.wallet = opts.wallet;
    this.db = new Database(opts.sqlitePath ?? 'ghost_policy.sqlite');
    this.initDb();
  }

  private initDb(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS policy_proposals (
        proposal_id TEXT PRIMARY KEY,
        ghost_id TEXT NOT NULL,
        delta_json TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        executable_at_ms INTEGER NOT NULL,
        status TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS policy_proposals_ghost_status
        ON policy_proposals (ghost_id, status);
    `);
  }

  async getCurrentPolicy(ghostId: Hex): Promise<Policy> {
    const cached = this.policyCache.get(ghostId);
    if (cached) return cached;

    const p = await this.wallet.getPolicy(ghostId);
    this.policyCache.set(ghostId, p);
    return p;
  }

  async refreshPolicy(ghostId: Hex): Promise<Policy> {
    const p = await this.wallet.getPolicy(ghostId);
    this.policyCache.set(ghostId, p);
    return p;
  }

  async handlePolicyChangedEvent(ghostId: Hex): Promise<Policy> {
    return this.refreshPolicy(ghostId);
  }

  saveProposal(row: {
    proposal_id: Hex;
    ghost_id: Hex;
    delta: PolicyDelta;
    created_at_ms: number;
    executable_at_ms: number;
  }): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO policy_proposals (
        proposal_id,
        ghost_id,
        delta_json,
        created_at_ms,
        executable_at_ms,
        status
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      row.proposal_id,
      row.ghost_id,
      serializePolicyDelta(row.delta),
      row.created_at_ms,
      row.executable_at_ms,
      'pending',
    );
  }

  getProposal(proposalId: Hex): PolicyProposalRow | null {
    const stmt = this.db.prepare(`
      SELECT proposal_id, ghost_id, delta_json, created_at_ms, executable_at_ms, status
      FROM policy_proposals
      WHERE proposal_id = ?
      LIMIT 1
    `);

    const r = stmt.get(proposalId) as
      | {
          proposal_id: string;
          ghost_id: string;
          delta_json: string;
          created_at_ms: number;
          executable_at_ms: number;
          status: ProposalStatus;
        }
      | undefined;

    if (!r) return null;

    return {
      proposal_id: r.proposal_id as Hex,
      ghost_id: r.ghost_id as Hex,
      delta: deserializePolicyDelta(r.delta_json),
      created_at_ms: r.created_at_ms,
      executable_at_ms: r.executable_at_ms,
      status: r.status,
    };
  }

  listPending(ghostId: Hex): PolicyProposalRow[] {
    const stmt = this.db.prepare(`
      SELECT proposal_id, ghost_id, delta_json, created_at_ms, executable_at_ms, status
      FROM policy_proposals
      WHERE ghost_id = ? AND status = 'pending'
      ORDER BY created_at_ms ASC
    `);

    const rows = stmt.all(ghostId) as Array<{
      proposal_id: string;
      ghost_id: string;
      delta_json: string;
      created_at_ms: number;
      executable_at_ms: number;
      status: ProposalStatus;
    }>;

    return rows.map((r) => ({
      proposal_id: r.proposal_id as Hex,
      ghost_id: r.ghost_id as Hex,
      delta: deserializePolicyDelta(r.delta_json),
      created_at_ms: r.created_at_ms,
      executable_at_ms: r.executable_at_ms,
      status: r.status,
    }));
  }

  markExecuted(proposalId: Hex): void {
    this.markStatus(proposalId, 'executed');
  }

  markCancelled(proposalId: Hex): void {
    this.markStatus(proposalId, 'cancelled');
  }

  private markStatus(proposalId: Hex, status: ProposalStatus): void {
    const stmt = this.db.prepare(`
      UPDATE policy_proposals
      SET status = ?
      WHERE proposal_id = ?
    `);

    stmt.run(status, proposalId);
  }
}

