import { randomBytes } from 'node:crypto';

export type ShamirShare = {
  // 1-indexed (1..n)
  index: number;
  // 32 bytes (one byte per vault-key byte position)
  data: Uint8Array;
};

export function encodeShare(share: ShamirShare): Uint8Array {
  if (!Number.isInteger(share.index) || share.index < 1 || share.index > 255) {
    throw new Error(`InvalidShareIndex:${share.index}`);
  }
  const out = new Uint8Array(1 + share.data.length);
  out[0] = share.index & 0xff;
  out.set(share.data, 1);
  return out;
}

export function decodeShare(bytes: Uint8Array): ShamirShare {
  if (bytes.length < 2) throw new Error('InvalidShareBytes');
  const index = bytes[0];
  if (index < 1) throw new Error(`InvalidShareIndex:${index}`);
  return { index, data: bytes.slice(1) };
}

// ---- GF(2^8) helpers (poly 0x11B) ----

export function gfAdd(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

export function gfMul(a: number, b: number): number {
  let x = a & 0xff;
  let y = b & 0xff;
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (y & 1) p ^= x;
    const hi = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi) x ^= 0x1b; // reduction for 0x11B
    y >>= 1;
  }
  return p & 0xff;
}

export function gfPow(a: number, e: number): number {
  let base = a & 0xff;
  let exp = e >>> 0;
  let out = 1;
  while (exp > 0) {
    if (exp & 1) out = gfMul(out, base);
    base = gfMul(base, base);
    exp >>>= 1;
  }
  return out & 0xff;
}

export function gfInv(a: number): number {
  const x = a & 0xff;
  if (x === 0) throw new Error('ZeroHasNoInverse');
  // a^(2^8-2) = a^254
  return gfPow(x, 254);
}

export function evalPolyAt(coeffs: Uint8Array, x: number): number {
  const xx = x & 0xff;
  let y = 0;
  // Horner: (((a_n)x + a_{n-1})x + ...)x + a_0
  for (let i = coeffs.length - 1; i >= 0; i--) {
    y = gfAdd(gfMul(y, xx), coeffs[i]);
  }
  return y & 0xff;
}

// ---- Shamir split / reconstruct ----

export function splitVaultKey(vaultKey: Uint8Array, threshold: number, totalShares: number): ShamirShare[] {
  if (vaultKey.length !== 32) throw new Error(`InvalidVaultKeyLength:${vaultKey.length}`);
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 255) throw new Error(`InvalidThreshold:${threshold}`);
  if (!Number.isInteger(totalShares) || totalShares < 1 || totalShares > 255) {
    throw new Error(`InvalidTotalShares:${totalShares}`);
  }
  if (threshold > totalShares) throw new Error(`ThresholdExceedsTotalShares:${threshold}:${totalShares}`);

  const shares: ShamirShare[] = [];
  for (let i = 1; i <= totalShares; i++) shares.push({ index: i, data: new Uint8Array(32) });

  for (let pos = 0; pos < 32; pos++) {
    const secretByte = vaultKey[pos] & 0xff;
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secretByte;
    if (threshold > 1) {
      const rand = randomBytes(threshold - 1);
      for (let j = 1; j < threshold; j++) coeffs[j] = rand[j - 1] & 0xff;
    }

    for (const s of shares) {
      const x = s.index & 0xff;
      s.data[pos] = evalPolyAt(coeffs, x);
    }
  }

  return shares;
}

export function reconstructVaultKey(shares: ShamirShare[], threshold: number): Uint8Array {
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 255) throw new Error(`InvalidThreshold:${threshold}`);
  if (shares.length < threshold) throw new Error(`InsufficientShares:${shares.length}:${threshold}`);

  // Select first `threshold` unique-index shares.
  const chosen: ShamirShare[] = [];
  const seen = new Set<number>();
  for (const s of shares) {
    if (!Number.isInteger(s.index) || s.index < 1 || s.index > 255) throw new Error(`InvalidShareIndex:${s.index}`);
    if (s.data.length !== 32) throw new Error(`InvalidShareDataLength:${s.data.length}`);
    if (seen.has(s.index)) continue;
    seen.add(s.index);
    chosen.push(s);
    if (chosen.length === threshold) break;
  }

  if (chosen.length < threshold) throw new Error(`InsufficientUniqueShares:${chosen.length}:${threshold}`);

  // Fast path for t=1: secret is share value.
  if (threshold === 1) {
    const out = chosen[0].data.slice();
    if (out.length !== 32) throw new Error(`InvalidReconstructedKeyLength:${out.length}`);
    return out;
  }

  const out = new Uint8Array(32);
  const xs = chosen.map((s) => s.index & 0xff);

  for (let pos = 0; pos < 32; pos++) {
    let secret = 0;

    for (let i = 0; i < chosen.length; i++) {
      const x_i = xs[i];
      const y_i = chosen[i].data[pos] & 0xff;

      let num = 1;
      let den = 1;
      for (let j = 0; j < chosen.length; j++) {
        if (j === i) continue;
        const x_j = xs[j];
        num = gfMul(num, x_j);
        den = gfMul(den, gfAdd(x_j, x_i)); // (x_j - x_i) in char-2 is XOR
      }

      const li0 = gfMul(num, gfInv(den));
      secret = gfAdd(secret, gfMul(y_i, li0));
    }

    out[pos] = secret & 0xff;
  }

  if (out.length !== 32) throw new Error(`InvalidReconstructedKeyLength:${out.length}`);
  return out;
}

