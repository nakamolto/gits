import type { Address, Hex } from 'viem';
import { unimplemented } from './_todo.js';

export class VerifierRegistry {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async registerVerifier(_asset: Address, _amount: bigint): Promise<void> {
    return unimplemented('VerifierRegistry.registerVerifier');
  }

  async increaseStake(_asset: Address, _amount: bigint): Promise<void> {
    return unimplemented('VerifierRegistry.increaseStake');
  }

  async beginDecreaseStake(_asset: Address, _amount: bigint): Promise<void> {
    return unimplemented('VerifierRegistry.beginDecreaseStake');
  }

  async withdrawDecreasedStake(_asset: Address): Promise<void> {
    return unimplemented('VerifierRegistry.withdrawDecreasedStake');
  }

  async slashVerifier(_verifier: Address, _asset: Address, _amount: bigint, _reason: Hex): Promise<void> {
    return unimplemented('VerifierRegistry.slashVerifier');
  }

  async proveVerifierEquivocation(
    _verifier: Address,
    _shell_id: Hex,
    _ac_payload_a: Hex,
    _sig_a: Hex,
    _ac_payload_b: Hex,
    _sig_b: Hex,
  ): Promise<void> {
    return unimplemented('VerifierRegistry.proveVerifierEquivocation');
  }

  async allowMeasurement(_measurement_hash: Hex, _tier_class: number, _nonce: bigint, _sigs_verifiers: Hex[]): Promise<void> {
    return unimplemented('VerifierRegistry.allowMeasurement');
  }

  async revokeMeasurement(_measurement_hash: Hex, _nonce: bigint, _sigs_verifiers: Hex[]): Promise<void> {
    return unimplemented('VerifierRegistry.revokeMeasurement');
  }

  async isActiveVerifier(_verifier: Address): Promise<boolean> {
    return unimplemented('VerifierRegistry.isActiveVerifier');
  }

  async stakeScore(_verifier: Address): Promise<bigint> {
    return unimplemented('VerifierRegistry.stakeScore');
  }

  async activeStake(_verifier: Address, _asset: Address): Promise<bigint> {
    return unimplemented('VerifierRegistry.activeStake');
  }

  async isMeasurementAllowed(_measurement_hash: Hex, _tier_class: number): Promise<boolean> {
    return unimplemented('VerifierRegistry.isMeasurementAllowed');
  }
}

