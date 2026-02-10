import type { Hex } from 'viem';

import type { Policy, PolicyDelta, ShellRecord } from '../../../sdk/src/types/structs.js';
import { LocalPolicyState } from '../config/policy.js';

export type PolicyDeltaClassification = 'tightening' | 'loosening' | 'mixed';

export interface GhostWalletPolicyClient {
  proposePolicyChange(ghostId: Hex, delta: PolicyDelta): Promise<Hex>;
  executePolicyChange(ghostId: Hex, proposalId: Hex): Promise<void>;
  cancelPolicyChange(ghostId: Hex, proposalId: Hex): Promise<void>;
}

export interface TecVerifier {
  verifyTec(ghostId: Hex, policy: Policy): Promise<boolean>;
}

export interface SessionReader {
  getCurrentShellId(ghostId: Hex): Promise<Hex>;
}

export interface ShellReader {
  getShell(shellId: Hex): Promise<ShellRecord>;
}

export class DefaultTecVerifier implements TecVerifier {
  private readonly sessions: SessionReader;
  private readonly shells: ShellReader;

  constructor(opts: { sessions: SessionReader; shells: ShellReader }) {
    this.sessions = opts.sessions;
    this.shells = opts.shells;
  }

  async verifyTec(ghostId: Hex, policy: Policy): Promise<boolean> {
    const currentShellId = await this.sessions.getCurrentShellId(ghostId);

    if (currentShellId === policy.home_shell) return true;
    if (policy.trusted_shells.includes(currentShellId)) return true;

    const shell = await this.shells.getShell(currentShellId);
    return shell.assurance_tier === 3 && !isZeroHex(shell.certificate_id);
  }
}

export class TimelockNotElapsed extends Error {
  readonly executableAtMs: number;
  readonly nowMs: number;

  constructor(executableAtMs: number, nowMs: number) {
    super(`Timelock not elapsed (now=${nowMs}, executable_at=${executableAtMs})`);
    this.executableAtMs = executableAtMs;
    this.nowMs = nowMs;
  }
}

export class TecNotVerified extends Error {
  constructor() {
    super('TEC not verified');
  }
}

export class UnknownProposal extends Error {
  constructor(proposalId: Hex) {
    super(`Unknown proposal: ${proposalId}`);
  }
}

export class MixedPolicyDeltaRejected extends Error {
  constructor() {
    super('Mixed policy deltas are rejected; split into tightening and loosening proposals');
  }
}

function isZeroHex(v: string): boolean {
  return /^0x0*$/i.test(v);
}

export function classifyDelta(current: Policy, delta: PolicyDelta): PolicyDeltaClassification {
  let tightening = false;
  let loosening = false;

  // Tightening signals.
  if (delta.remove_trusted_shells.length > 0) tightening = true;
  if (delta.remove_allowed_shells.length > 0) tightening = true;
  if (delta.hot_allowance_delta < 0n) tightening = true;
  if (delta.escape_gas_delta > 0n) tightening = true;
  if (delta.escape_stable_delta > 0n) tightening = true;

  // Loosening signals.
  if (delta.add_trusted_shells.length > 0) loosening = true;
  if (delta.add_allowed_shells.length > 0) loosening = true;
  if (delta.hot_allowance_delta > 0n) loosening = true;
  if (delta.escape_gas_delta < 0n) loosening = true;
  if (delta.escape_stable_delta < 0n) loosening = true;
  if (!isZeroHex(delta.new_home_shell)) loosening = true;

  // Guardians: new_guardians replaces the entire set. Compare to current policy to detect add vs remove.
  if (delta.new_guardians.length > 0) {
    const currentSet = new Set(current.guardians);
    const nextSet = new Set(delta.new_guardians);
    const added = delta.new_guardians.some((g) => !currentSet.has(g));
    const removed = current.guardians.some((g) => !nextSet.has(g));
    if (added) tightening = true;
    if (removed) loosening = true;
  }

  // t_guardian: new_t_guardian is absolute (0 = no change).
  if (delta.new_t_guardian !== 0n) {
    if (delta.new_t_guardian > current.t_guardian) tightening = true;
    if (delta.new_t_guardian < current.t_guardian) loosening = true;
  }

  // Roaming config is ambiguous to parse here; be conservative and require timelock + TEC.
  if (delta.roaming_config !== '0x' && !isZeroHex(delta.roaming_config)) {
    loosening = true;
  }

  if (tightening && loosening) return 'mixed';
  if (tightening) return 'tightening';
  if (loosening) return 'loosening';

  // No-op deltas are neither tightening nor loosening; treat as tightening (no timelock).
  return 'tightening';
}

export class PolicyEngine {
  private readonly wallet: GhostWalletPolicyClient;
  private readonly policyState: LocalPolicyState;
  private readonly timelockMs: number;
  private readonly nowMs: () => number;
  private readonly tecVerifier: TecVerifier;

  constructor(opts: {
    wallet: GhostWalletPolicyClient;
    policyState: LocalPolicyState;
    timelockMs: number;
    tecVerifier: TecVerifier;
    nowMs?: () => number;
  }) {
    this.wallet = opts.wallet;
    this.policyState = opts.policyState;
    this.timelockMs = opts.timelockMs;
    this.tecVerifier = opts.tecVerifier;
    this.nowMs = opts.nowMs ?? Date.now;
  }

  classifyDelta(current: Policy, delta: PolicyDelta): PolicyDeltaClassification {
    return classifyDelta(current, delta);
  }

  async applyTightening(ghostId: Hex, delta: PolicyDelta): Promise<Hex> {
    const proposalId = await this.wallet.proposePolicyChange(ghostId, delta);
    await this.wallet.executePolicyChange(ghostId, proposalId);
    await this.policyState.refreshPolicy(ghostId);
    return proposalId;
  }

  async proposeLoosening(ghostId: Hex, delta: PolicyDelta): Promise<Hex> {
    const proposalId = await this.wallet.proposePolicyChange(ghostId, delta);

    const createdAtMs = this.nowMs();
    const executableAtMs = createdAtMs + this.timelockMs;

    this.policyState.saveProposal({
      proposal_id: proposalId,
      ghost_id: ghostId,
      delta,
      created_at_ms: createdAtMs,
      executable_at_ms: executableAtMs,
    });

    return proposalId;
  }

  async executePending(ghostId: Hex, proposalId: Hex): Promise<void> {
    const p = this.policyState.getProposal(proposalId);
    if (!p) throw new UnknownProposal(proposalId);

    const now = this.nowMs();
    if (now < p.executable_at_ms) throw new TimelockNotElapsed(p.executable_at_ms, now);

    const currentPolicy = await this.policyState.getCurrentPolicy(ghostId);
    const tecOk = await this.tecVerifier.verifyTec(ghostId, currentPolicy);
    if (!tecOk) throw new TecNotVerified();

    await this.wallet.executePolicyChange(ghostId, proposalId);
    this.policyState.markExecuted(proposalId);
    await this.policyState.refreshPolicy(ghostId);
  }

  async cancelPending(_ghostId: Hex, proposalId: Hex): Promise<void> {
    await this.wallet.cancelPolicyChange(_ghostId, proposalId);
    this.policyState.markCancelled(proposalId);
  }
}
