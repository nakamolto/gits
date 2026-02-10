import type { Address, Hex } from 'viem';
import type { AuthSig, RBC, SessionParams, SessionState, ShareReceipt } from '../types/structs.js';
import { unimplemented } from './_todo.js';

export class SessionManager {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async openSession(_ghost_id: Hex, _shell_id: Hex, _params: SessionParams): Promise<void> {
    return unimplemented('SessionManager.openSession');
  }

  async renewLease(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.renewLease');
  }

  async closeSession(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.closeSession');
  }

  async fundNextEpoch(_session_id: bigint, _amount: bigint): Promise<void> {
    return unimplemented('SessionManager.fundNextEpoch');
  }

  async settleEpoch(_session_id: bigint, _epoch: bigint, _su_delivered: bigint): Promise<void> {
    return unimplemented('SessionManager.settleEpoch');
  }

  async startMigration(_ghost_id: Hex, _to_shell_id: Hex, _bundle_hash: Hex): Promise<void> {
    return unimplemented('SessionManager.startMigration');
  }

  async cancelMigration(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.cancelMigration');
  }

  async finalizeMigration(_ghost_id: Hex, _to_shell_id: Hex, _proof: Hex): Promise<void> {
    return unimplemented('SessionManager.finalizeMigration');
  }

  async startRecovery(_ghost_id: Hex): Promise<bigint> {
    return unimplemented('SessionManager.startRecovery');
  }

  async recoveryRotate(
    _ghost_id: Hex,
    _attempt_id: bigint,
    _new_identity_pubkey: Hex,
    _rbc: RBC,
    _rs_list: Hex[],
    _sigs: AuthSig[],
    _share_receipts: ShareReceipt[],
  ): Promise<void> {
    return unimplemented('SessionManager.recoveryRotate');
  }

  async expireRecovery(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.expireRecovery');
  }

  async takeoverRecovery(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.takeoverRecovery');
  }

  async exitRecovery(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.exitRecovery');
  }

  async proveSafeHavenEquivocation(
    _shell_id: Hex,
    _ghost_id: Hex,
    _attempt_id: bigint,
    _checkpoint_commitment: Hex,
    _pk_new_a: Hex,
    _sig_a: Hex,
    _pk_new_b: Hex,
    _sig_b: Hex,
  ): Promise<void> {
    return unimplemented('SessionManager.proveSafeHavenEquivocation');
  }

  async getSession(_ghost_id: Hex): Promise<SessionState> {
    return unimplemented('SessionManager.getSession');
  }

  async getSessionById(_session_id: bigint): Promise<SessionState> {
    return unimplemented('SessionManager.getSessionById');
  }

  async getSessionKeys(_session_id: bigint): Promise<{ ghost_key: Hex; shell_key: Hex; submitter: Address }> {
    return unimplemented('SessionManager.getSessionKeys');
  }

  async effectiveTenureExpiry(_ghost_id: Hex): Promise<bigint> {
    return unimplemented('SessionManager.effectiveTenureExpiry');
  }

  async isRefreshAnchor(_ghost_id: Hex, _shell_id: Hex): Promise<boolean> {
    return unimplemented('SessionManager.isRefreshAnchor');
  }

  async isActiveRecoveryInitiator(_shell_id: Hex): Promise<boolean> {
    return unimplemented('SessionManager.isActiveRecoveryInitiator');
  }

  async processExpiry(_ghost_id: Hex): Promise<void> {
    return unimplemented('SessionManager.processExpiry');
  }
}

