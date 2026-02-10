import type { Hex } from 'viem';

// GITS Part 3 (Implementation Spec, Feb 2026) — Section 14.9 test vectors.
export const part3_14_9 = {
  chain_id: 8453n,
  session_id: 123456789n,
  epoch: 42n,

  tag_hashes: {
    GITS_HEARTBEAT: '0x79f3a1c02ce8092087b1229f734556ce9d5886b412f39e9e13653520d21a8f30' as Hex,
    GITS_SHARE: '0x0f585af21ff7f28eb5d968fdcddf0d555a846e2ed37ff53dda9214ae28900e04' as Hex,
    GITS_SHARE_ACK: '0xaff245e7cf289589c58f50746424ad2c71b5717a7e635086811cd93d86a77582' as Hex,
    GITS_LOG_LEAF: '0xf6294a134bf83bf27e2d5a64e3bcfce55373e74cedf22e996eba267a3db88fee' as Hex,
    GITS_LOG_NODE: '0x8ff17f274aafeacb48bcc81cc0419089924a701538706d5eed0f7bac62e98ca5' as Hex,
  },

  vector_a: {
    interval_index: 17n,
    expected: '0x346279e72db9f82fa31c03c8fab3278f83b2797b4cdd9b7a2ba879f4bc9da621' as Hex,
  },

  vector_b: {
    ghost_id: '0x7f36bb45ea0ff17cdefa9d9cae3247c526985b0c14c8903be7b354961ad89123' as Hex,
    attempt_id: 3n,
    checkpoint_commitment: '0x5b31a77e397fbe08a819b514a2f468be97009d2c4210a159b74d4b9a6fd6f4d9' as Hex,
    envelope_commitment: '0xde00a0f376943b7461641517e69ae49a6c5161c3e05fc28f5c14f154b551c79c' as Hex,
    expected: '0x377e3c007216a5ed98ceec809e3cbc9967de57cf24b24739eb1324bb83dcfb7b' as Hex,
  },

  vector_c: {
    envelope_commitment: '0xde00a0f376943b7461641517e69ae49a6c5161c3e05fc28f5c14f154b551c79c' as Hex,
    expected: '0x734b462d3e98bd28040d76cdc724ee8217204fb476b8cd1522a641436b057b35' as Hex,
  },

  sigs: {
    // seq(0x01..0x41), 65 bytes.
    sig_ghost_seq_65:
      '0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041' as Hex,
    // seq(0x65..0xa5), 65 bytes.
    sig_shell_seq_65:
      '0x65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5' as Hex,
    // 65 bytes of 0x22.
    sig_ghost_22_65:
      '0x2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222' as Hex,
    // 65 bytes of 0x33.
    sig_shell_33_65:
      '0x3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333' as Hex,
  },

  vector_d: {
    interval_index: 17,
    v_i: 1 as const,
    h_sig_ghost_expected: '0x752e968b7f3a77a413a39ffce9f0940703720b705679a9617e303f591a695b30' as Hex,
    h_sig_shell_expected: '0xd763f1b001827c81fd63e0481fab326731ad2f2bdc2e61458e10cfc430a7fe00' as Hex,
    expected: '0x3bd00fdcc06781ca996db6dfb070370eaf44b54b2e53e15ba53af9cb5a9adc45' as Hex,
  },

  vector_e: {
    // Right leaf (interval_index = 18, v=0, sigs empty).
    leaf_hash_18: '0xeea8fec70a6cc83f8921b68392f325c83995bde1edb3ba04b94003adbc06b3aa' as Hex,
    expected: '0x43b9228b9e0b50ae2cd9318bce993781b6cae6d741785b619af56441008097ff' as Hex,
    expected_sum: 1,
  },

  vector_f: {
    n_pad: 4,
    expected_root: '0xb7b7c48afe3c285065cf61d09b7eb454e18e51bed622e22ad2ff758a1b0f7c2a' as Hex,
    expected_su_delivered: 2,
  },
} as const;

