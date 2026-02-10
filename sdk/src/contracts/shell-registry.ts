import type { Address, Hex } from 'viem';
import type { ShellRecord } from '../types/structs.js';
import { unimplemented } from './_todo.js';

export class ShellRegistry {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async registerShell(
    _shell_id: Hex,
    _identity_pubkey: Hex,
    _offer_signer_pubkey: Hex,
    _payout_address: Address,
    _salt: Hex,
    _bond_asset: Address,
    _bond_amount: bigint,
    _cert: Hex,
    _sigs_cert: Hex[],
    _sig: Hex,
  ): Promise<void> {
    return unimplemented('ShellRegistry.registerShell');
  }

  async proposeIdentityKeyUpdate(_shell_id: Hex, _new_identity_pubkey: Hex, _proof: Hex): Promise<void> {
    return unimplemented('ShellRegistry.proposeIdentityKeyUpdate');
  }

  async confirmIdentityKeyUpdate(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.confirmIdentityKeyUpdate');
  }

  async proposeOfferSignerUpdate(_shell_id: Hex, _new_offer_signer_pubkey: Hex): Promise<void> {
    return unimplemented('ShellRegistry.proposeOfferSignerUpdate');
  }

  async confirmOfferSignerUpdate(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.confirmOfferSignerUpdate');
  }

  async proposeRecoveryKeyUpdate(_shell_id: Hex, _new_recovery_pubkey: Hex): Promise<void> {
    return unimplemented('ShellRegistry.proposeRecoveryKeyUpdate');
  }

  async confirmRecoveryKeyUpdate(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.confirmRecoveryKeyUpdate');
  }

  async updateCapabilityHash(_shell_id: Hex, _new_capability_hash: Hex): Promise<void> {
    return unimplemented('ShellRegistry.updateCapabilityHash');
  }

  async setPayoutAddress(_shell_id: Hex, _new_payout_address: Address): Promise<void> {
    return unimplemented('ShellRegistry.setPayoutAddress');
  }

  async setCertificate(_shell_id: Hex, _cert_data: Hex, _sigs_verifiers: Hex[]): Promise<void> {
    return unimplemented('ShellRegistry.setCertificate');
  }

  async revokeCertificate(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.revokeCertificate');
  }

  async beginUnbond(_shell_id: Hex, _amount: bigint): Promise<void> {
    return unimplemented('ShellRegistry.beginUnbond');
  }

  async finalizeUnbond(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.finalizeUnbond');
  }

  async bondSafeHaven(_shell_id: Hex, _amount: bigint): Promise<void> {
    return unimplemented('ShellRegistry.bondSafeHaven');
  }

  async beginUnbondSafeHaven(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.beginUnbondSafeHaven');
  }

  async finalizeUnbondSafeHaven(_shell_id: Hex): Promise<void> {
    return unimplemented('ShellRegistry.finalizeUnbondSafeHaven');
  }

  async slashShell(_shell_id: Hex, _amount: bigint, _reason: Hex): Promise<void> {
    return unimplemented('ShellRegistry.slashShell');
  }

  async slashSafeHaven(_shell_id: Hex, _amount: bigint, _challenger: Address): Promise<void> {
    return unimplemented('ShellRegistry.slashSafeHaven');
  }

  async getShell(_shell_id: Hex): Promise<ShellRecord> {
    return unimplemented('ShellRegistry.getShell');
  }

  async assuranceTier(_shell_id: Hex): Promise<number> {
    return unimplemented('ShellRegistry.assuranceTier');
  }
}

