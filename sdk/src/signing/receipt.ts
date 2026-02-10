import { encodeAbiParameters, keccak256, toBytes } from 'viem';
import type { Hex } from 'viem';

const TAG_LEAF = keccak256(toBytes('GITS_LOG_LEAF'));
const TAG_NODE = keccak256(toBytes('GITS_LOG_NODE'));

export type IntervalData = {
  v_i: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
};

export type MerkleSumNode = {
  hash: Hex;
  sum: number;
};

export type ReceiptLeaf = {
  interval_index: number;
  v_i: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
  leaf_hash: Hex;
  leaf_sum: number;
};

export type MerkleTree = {
  root: Hex;
  su_total: number;
  leaves: ReceiptLeaf[];
  levels: MerkleSumNode[][];
};

export function logLeafHash(args: {
  chain_id: bigint;
  session_id: bigint;
  epoch: bigint;
  interval_index: number;
  v_i: 0 | 1;
  sig_ghost: Hex;
  sig_shell: Hex;
}): Hex {
  const { chain_id, session_id, epoch, interval_index, v_i, sig_ghost, sig_shell } = args;

  if (!Number.isInteger(interval_index) || interval_index < 0 || interval_index > 0xffffffff) {
    throw new Error('logLeafHash: interval_index must be a uint32');
  }

  const h_sig_ghost = keccak256(sig_ghost);
  const h_sig_shell = keccak256(sig_shell);

  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint32' },
        { type: 'uint8' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [TAG_LEAF, chain_id, session_id, epoch, interval_index, v_i, h_sig_ghost, h_sig_shell],
    ),
  );
}

export function logNodeHash(args: { hL: Hex; hR: Hex; sL: number; sR: number }): Hex {
  const { hL, hR, sL, sR } = args;
  if (!Number.isInteger(sL) || sL < 0 || sL > 0xffffffff) throw new Error('logNodeHash: sL must be a uint32');
  if (!Number.isInteger(sR) || sR < 0 || sR > 0xffffffff) throw new Error('logNodeHash: sR must be a uint32');

  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint32' },
        { type: 'uint32' },
      ],
      [TAG_NODE, hL, hR, sL, sR],
    ),
  );
}

function nextPow2(n: number): number {
  if (n <= 1) return 1;
  let p = 1;
  while (p < n) p *= 2;
  return p;
}

export function buildReceiptTree(args: {
  chain_id: bigint;
  session_id: bigint;
  epoch: bigint;
  intervals: IntervalData[];
}): MerkleTree {
  const { chain_id, session_id, epoch, intervals } = args;
  const n = intervals.length;
  const n_pad = nextPow2(n);

  const leaves: ReceiptLeaf[] = [];
  for (let i = 0; i < n_pad; i++) {
    const interval = i < n ? intervals[i] : { v_i: 0 as const, sig_ghost: '0x' as Hex, sig_shell: '0x' as Hex };
    const leaf_hash = logLeafHash({
      chain_id,
      session_id,
      epoch,
      interval_index: i,
      v_i: interval.v_i,
      sig_ghost: interval.sig_ghost,
      sig_shell: interval.sig_shell,
    });

    leaves.push({
      interval_index: i,
      v_i: interval.v_i,
      sig_ghost: interval.sig_ghost,
      sig_shell: interval.sig_shell,
      leaf_hash,
      leaf_sum: interval.v_i,
    });
  }

  const level0: MerkleSumNode[] = leaves.map((l) => ({ hash: l.leaf_hash, sum: l.leaf_sum }));
  const levels: MerkleSumNode[][] = [level0];

  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next: MerkleSumNode[] = [];

    for (let i = 0; i < prev.length; i += 2) {
      const L = prev[i];
      const R = prev[i + 1];
      const sum = L.sum + R.sum;
      const hash = logNodeHash({ hL: L.hash, hR: R.hash, sL: L.sum, sR: R.sum });
      next.push({ hash, sum });
    }

    levels.push(next);
  }

  const rootNode = levels[levels.length - 1][0];

  return {
    root: rootNode.hash,
    su_total: rootNode.sum,
    leaves,
    levels,
  };
}

export type FraudProofData = {
  candidate_id: bigint;
  interval_index: number;
  claimed_v: 0 | 1;
  leaf_hash: Hex;
  sibling_hashes: Hex[];
  sibling_sums: number[];
  sig_ghost: Hex;
  sig_shell: Hex;
};

export function generateFraudProof(tree: MerkleTree, interval_index: number, candidate_id: bigint = 0n): FraudProofData {
  if (!Number.isInteger(interval_index) || interval_index < 0 || interval_index >= tree.leaves.length) {
    throw new Error('generateFraudProof: interval_index out of range');
  }

  const leaf = tree.leaves[interval_index];
  const sibling_hashes: Hex[] = [];
  const sibling_sums: number[] = [];

  let idx = interval_index;
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level];
    const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
    sibling_hashes.push(nodes[sib].hash);
    sibling_sums.push(nodes[sib].sum);
    idx = Math.floor(idx / 2);
  }

  return {
    candidate_id,
    interval_index,
    claimed_v: leaf.v_i,
    leaf_hash: leaf.leaf_hash,
    sibling_hashes,
    sibling_sums,
    sig_ghost: leaf.sig_ghost,
    sig_shell: leaf.sig_shell,
  };
}
