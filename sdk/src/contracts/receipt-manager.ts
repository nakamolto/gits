import type { Address, Hex } from 'viem';
import type { ReceiptCandidate, FraudProof, FinalReceipt } from '../types/structs.js';
import { unimplemented } from './_todo.js';

export class ReceiptManager {
  public readonly address: Address;

  constructor(address: Address) {
    this.address = address;
  }

  async submitReceiptCandidate(_session_id: bigint, _epoch: bigint, _candidate: ReceiptCandidate): Promise<void> {
    return unimplemented('ReceiptManager.submitReceiptCandidate');
  }

  async challengeReceipt(_session_id: bigint, _epoch: bigint, _proof: FraudProof): Promise<void> {
    return unimplemented('ReceiptManager.challengeReceipt');
  }

  async challengeReceiptDA(_session_id: bigint, _epoch: bigint, _candidate_id: bigint): Promise<void> {
    return unimplemented('ReceiptManager.challengeReceiptDA');
  }

  async publishReceiptLog(_session_id: bigint, _epoch: bigint, _candidate_id: bigint, _encoded_log: Hex): Promise<void> {
    return unimplemented('ReceiptManager.publishReceiptLog');
  }

  async resolveReceiptDA(_session_id: bigint, _epoch: bigint, _candidate_id: bigint): Promise<void> {
    return unimplemented('ReceiptManager.resolveReceiptDA');
  }

  async finalizeReceipt(_session_id: bigint, _epoch: bigint): Promise<void> {
    return unimplemented('ReceiptManager.finalizeReceipt');
  }

  async getFinalReceipt(_session_id: bigint, _epoch: bigint): Promise<FinalReceipt> {
    return unimplemented('ReceiptManager.getFinalReceipt');
  }

  async pendingDACount(_epoch: bigint): Promise<bigint> {
    return unimplemented('ReceiptManager.pendingDACount');
  }
}
