import { describe, expect, it } from 'vitest';

import { keccak256, recoverAddress, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { heartbeatDigest, signHeartbeat } from '../src/signing/heartbeat.js';
import { shareAckDigest, shareDigest } from '../src/signing/digests.js';
import { logLeafHash, logNodeHash } from '../src/signing/receipt.js';
import { ghostRotateSignerDigest } from '../src/signing/rotation.js';

import { part3_14_9 } from './vectors/part3_14_9.js';

describe('Signing digests (Part 3 vectors)', () => {
  it('matches tag hashes (A–E)', () => {
    expect(keccak256(toBytes('GITS_HEARTBEAT'))).toBe(part3_14_9.tag_hashes.GITS_HEARTBEAT);
    expect(keccak256(toBytes('GITS_SHARE'))).toBe(part3_14_9.tag_hashes.GITS_SHARE);
    expect(keccak256(toBytes('GITS_SHARE_ACK'))).toBe(part3_14_9.tag_hashes.GITS_SHARE_ACK);
    expect(keccak256(toBytes('GITS_LOG_LEAF'))).toBe(part3_14_9.tag_hashes.GITS_LOG_LEAF);
    expect(keccak256(toBytes('GITS_LOG_NODE'))).toBe(part3_14_9.tag_hashes.GITS_LOG_NODE);
  });

  it('Vector A: heartbeatDigest', () => {
    const hb = heartbeatDigest({
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      interval_index: part3_14_9.vector_a.interval_index,
    });
    expect(hb).toBe(part3_14_9.vector_a.expected);
  });

  it('Vector B: shareDigest', () => {
    const d = shareDigest({
      chain_id: part3_14_9.chain_id,
      ghost_id: part3_14_9.vector_b.ghost_id,
      attempt_id: part3_14_9.vector_b.attempt_id,
      checkpoint_commitment: part3_14_9.vector_b.checkpoint_commitment,
      envelope_commitment: part3_14_9.vector_b.envelope_commitment,
    });
    expect(d).toBe(part3_14_9.vector_b.expected);
  });

  it('Vector C: shareAckDigest', () => {
    const d = shareAckDigest({
      chain_id: part3_14_9.chain_id,
      ghost_id: part3_14_9.vector_b.ghost_id,
      attempt_id: part3_14_9.vector_b.attempt_id,
      checkpoint_commitment: part3_14_9.vector_b.checkpoint_commitment,
      envelope_commitment: part3_14_9.vector_c.envelope_commitment,
    });
    expect(d).toBe(part3_14_9.vector_c.expected);
  });

  it('Vector D: logLeafHash (and intermediate H(sig))', () => {
    const { sig_ghost_seq_65, sig_shell_seq_65 } = part3_14_9.sigs;

    expect(keccak256(sig_ghost_seq_65)).toBe(part3_14_9.vector_d.h_sig_ghost_expected);
    expect(keccak256(sig_shell_seq_65)).toBe(part3_14_9.vector_d.h_sig_shell_expected);

    const leaf = logLeafHash({
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      interval_index: part3_14_9.vector_d.interval_index,
      v_i: part3_14_9.vector_d.v_i,
      sig_ghost: sig_ghost_seq_65,
      sig_shell: sig_shell_seq_65,
    });
    expect(leaf).toBe(part3_14_9.vector_d.expected);
  });

  it('Vector E: logNodeHash', () => {
    const leaf18 = logLeafHash({
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      interval_index: 18,
      v_i: 0,
      sig_ghost: '0x',
      sig_shell: '0x',
    });
    expect(leaf18).toBe(part3_14_9.vector_e.leaf_hash_18);

    const node = logNodeHash({
      hL: part3_14_9.vector_d.expected,
      hR: part3_14_9.vector_e.leaf_hash_18,
      sL: 1,
      sR: 0,
    });
    expect(node).toBe(part3_14_9.vector_e.expected);
  });

  it('ghostRotateSignerDigest: deterministic with nonce replay prevention', () => {
    const ghost_id = part3_14_9.vector_b.ghost_id;
    const new_pubkey = '0xaabbccdd' as `0x${string}`;
    const chain_id = part3_14_9.chain_id;
    const nonce = 0n;

    // Deterministic: same inputs → same output
    const d1 = ghostRotateSignerDigest({ ghost_id, new_identity_pubkey: new_pubkey, chain_id, nonce });
    const d2 = ghostRotateSignerDigest({ ghost_id, new_identity_pubkey: new_pubkey, chain_id, nonce });
    expect(d1).toBe(d2);

    // Different nonce → different digest (replay prevention)
    const d3 = ghostRotateSignerDigest({ ghost_id, new_identity_pubkey: new_pubkey, chain_id, nonce: 1n });
    expect(d3).not.toBe(d1);

    // Different chain_id → different digest (cross-chain replay prevention)
    const d4 = ghostRotateSignerDigest({ ghost_id, new_identity_pubkey: new_pubkey, chain_id: 1n, nonce });
    expect(d4).not.toBe(d1);
  });

  it('signHeartbeat: signature recovers signer address', async () => {
    const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

    const args = {
      chain_id: part3_14_9.chain_id,
      session_id: part3_14_9.session_id,
      epoch: part3_14_9.epoch,
      interval_index: part3_14_9.vector_a.interval_index,
    } as const;

    const hash = heartbeatDigest(args);
    const signature = await signHeartbeat(account, args);
    const recovered = await recoverAddress({ hash, signature });
    expect(recovered).toBe(account.address);
  });
});

