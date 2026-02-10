import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Address, Hex } from 'viem';

// Part 3 spec, Section 10.5.2: receipt_id = keccak256(abi.encode(keccak256(bytes("GITS_RECEIPT_ID")), ...))
const TAG_HASH = keccak256(toBytes('GITS_RECEIPT_ID'));

export function deriveReceiptId(
  chain_id: bigint,
  receipt_manager_address: Address,
  session_id: bigint,
  epoch: bigint,
): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'uint256' },
        { type: 'uint256' },
      ],
      [TAG_HASH, chain_id, receipt_manager_address, session_id, epoch],
    ),
  );
}

