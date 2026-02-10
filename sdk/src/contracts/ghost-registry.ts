import type { Address, Hex } from 'viem';
import type { GhostRecord, RecoveryConfig } from '../types/structs.js';
import { unimplemented } from './_todo.js';

export class GhostRegistry {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async registerGhost(
    _ghost_id: Hex,
    _identity_pubkey: Hex,
    _wallet: Address,
    _salt: Hex,
    _recovery_config: RecoveryConfig,
  ): Promise<void> {
    return unimplemented('GhostRegistry.registerGhost');
  }

  async bondGhost(_ghost_id: Hex, _asset: Address, _amount: bigint): Promise<void> {
    return unimplemented('GhostRegistry.bondGhost');
  }

  async beginUnbondGhost(_ghost_id: Hex, _amount: bigint): Promise<void> {
    return unimplemented('GhostRegistry.beginUnbondGhost');
  }

  async finalizeUnbondGhost(_ghost_id: Hex): Promise<void> {
    return unimplemented('GhostRegistry.finalizeUnbondGhost');
  }

  async ghostPassportEligible(_ghost_id: Hex, _epoch: bigint): Promise<boolean> {
    return unimplemented('GhostRegistry.ghostPassportEligible');
  }

  async rotateSigner(_ghost_id: Hex, _new_identity_pubkey: Hex, _proof: Hex): Promise<void> {
    return unimplemented('GhostRegistry.rotateSigner');
  }

  async publishCheckpoint(
    _ghost_id: Hex,
    _epoch: bigint,
    _checkpoint_commitment: Hex,
    _envelope_commitment: Hex,
    _ptr_checkpoint: Hex,
    _ptr_envelope: Hex,
  ): Promise<void> {
    return unimplemented('GhostRegistry.publishCheckpoint');
  }

  async setRecoveryConfig(_ghost_id: Hex, _recovery_config: RecoveryConfig): Promise<void> {
    return unimplemented('GhostRegistry.setRecoveryConfig');
  }

  async getGhost(_ghost_id: Hex): Promise<GhostRecord> {
    return unimplemented('GhostRegistry.getGhost');
  }
}

