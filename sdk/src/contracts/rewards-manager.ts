import type { Address, Hex } from 'viem';
import { unimplemented } from './_todo.js';

export class RewardsManager {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async recordReceipt(
    _receipt_id: Hex,
    _epoch: bigint,
    _ghost_id: Hex,
    _shell_id: Hex,
    _su_delivered: number,
    _weight_q: bigint,
  ): Promise<void> {
    return unimplemented('RewardsManager.recordReceipt');
  }

  async finalizeEpoch(_epoch: bigint): Promise<void> {
    return unimplemented('RewardsManager.finalizeEpoch');
  }

  async claimReceiptRewards(_receipt_id: Hex): Promise<void> {
    return unimplemented('RewardsManager.claimReceiptRewards');
  }

  async pruneEpoch(_epoch: bigint): Promise<void> {
    return unimplemented('RewardsManager.pruneEpoch');
  }

  async pruneReceipt(_receipt_id: Hex): Promise<void> {
    return unimplemented('RewardsManager.pruneReceipt');
  }
}
