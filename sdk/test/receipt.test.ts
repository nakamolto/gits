import { describe, expect, it } from 'vitest';

import { buildReceiptTree, generateFraudProof, logNodeHash } from '../src/signing/receipt.js';
import { part3_14_9 } from './vectors/part3_14_9.js';

describe('Receipt Merkle-sum tree (Part 3 vectors)', () => {
  it('Vector F: buildReceiptTree root + su_total', () => {
    const intervals = [
      { v_i: 1 as const, sig_ghost: part3_14_9.sigs.sig_ghost_seq_65, sig_shell: part3_14_9.sigs.sig_shell_seq_65 },
      { v_i: 0 as const, sig_ghost: '0x', sig_shell: '0x' },
      { v_i: 1 as const, sig_ghost: part3_14_9.sigs.sig_ghost_22_65, sig_shell: part3_14_9.sigs.sig_shell_33_65 },
      { v_i: 0 as const, sig_ghost: '0x', sig_shell: '0x' },
    ];

    const tree = buildReceiptTree({
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      intervals,
    });

    expect(tree.root).toBe(part3_14_9.vector_f.expected_root);
    expect(tree.su_total).toBe(part3_14_9.vector_f.expected_su_delivered);
    expect(tree.leaves).toHaveLength(part3_14_9.vector_f.n_pad);
  });

  it('generateFraudProof: recomputes root from proof', () => {
    const intervals = [
      { v_i: 1 as const, sig_ghost: part3_14_9.sigs.sig_ghost_seq_65, sig_shell: part3_14_9.sigs.sig_shell_seq_65 },
      { v_i: 0 as const, sig_ghost: '0x', sig_shell: '0x' },
      { v_i: 1 as const, sig_ghost: part3_14_9.sigs.sig_ghost_22_65, sig_shell: part3_14_9.sigs.sig_shell_33_65 },
      { v_i: 0 as const, sig_ghost: '0x', sig_shell: '0x' },
    ];

    const tree = buildReceiptTree({
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      intervals,
    });

    const interval_index = 2;
    const proof = generateFraudProof(tree, interval_index, 7n);

    let h = proof.leaf_hash;
    let s = proof.claimed_v;
    let idx = proof.interval_index;

    for (let level = 0; level < proof.sibling_hashes.length; level++) {
      const sibH = proof.sibling_hashes[level];
      const sibS = proof.sibling_sums[level];

      const isLeft = idx % 2 === 0;
      const hL = isLeft ? h : sibH;
      const hR = isLeft ? sibH : h;
      const sL = isLeft ? s : sibS;
      const sR = isLeft ? sibS : s;

      h = logNodeHash({ hL, hR, sL, sR });
      s = sL + sR;
      idx = Math.floor(idx / 2);
    }

    expect(h).toBe(tree.root);
    expect(s).toBe(tree.su_total);
    expect(proof.candidate_id).toBe(7n);
  });
});

