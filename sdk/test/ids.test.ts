import { describe, expect, it } from 'vitest';

import { encodeAbiParameters } from 'viem';
import type { Address, Hex } from 'viem';

import { deriveGhostId } from '../src/ids/ghost-id.js';
import { deriveShellId } from '../src/ids/shell-id.js';
import { deriveReceiptId } from '../src/ids/receipt-id.js';

function k1IdentityPubkey(addr: Address): Hex {
  const pk_bytes = encodeAbiParameters([{ type: 'address' }], [addr]);
  return encodeAbiParameters([{ type: 'uint8' }, { type: 'bytes' }], [1n, pk_bytes]);
}

describe('ID derivation', () => {
  it('deriveGhostId (Part 3 Vector G inputs)', () => {
    const identity_pubkey = k1IdentityPubkey('0x1111111111111111111111111111111111110123');
    const wallet: Address = '0x2222222222222222222222222222222222225678';
    const salt: Hex = ('0x' + '0'.repeat(63) + '1') as Hex;

    const ghost_id = deriveGhostId(identity_pubkey, wallet, salt);

    // Computed from the Part 3 spec (Feb 2026), Section 14.9 Vector G inputs.
    expect(ghost_id).toBe('0xe3e2cf5fea968ce68f0dfa0cc0127ba52f0733a08f503dea87699ab31b92915d');
  });

  it('deriveShellId (Part 3 Vector H inputs)', () => {
    const identity_pubkey = k1IdentityPubkey('0x3333333333333333333333333333333333339abc');
    const salt: Hex = ('0x' + '0'.repeat(63) + '2') as Hex;

    const shell_id = deriveShellId(identity_pubkey, salt);

    // Computed from the Part 3 spec (Feb 2026), Section 14.9 Vector H inputs.
    expect(shell_id).toBe('0x9d1fd125887aa79bc752c70c795b8ed90ef2280a0bcf9814be44dc2a16d6b5a0');
  });

  it('deriveReceiptId (Part 3 receipt_id definition)', () => {
    const receipt_id = deriveReceiptId(
      8453n,
      '0x9999999999999999999999999999999999999999',
      123456789n,
      42n,
    );

    expect(receipt_id).toBe('0x8e1e3971dd8fd4082cf0264b6e6de075487f8266a2cdb016f05b61172d400e2a');
  });
});

