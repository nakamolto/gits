const Q64 = 1n << 64n;

export function mulDiv(a: bigint, b: bigint, c: bigint): bigint {
  if (c === 0n) throw new Error('mulDiv: division by zero');
  return (a * b) / c;
}

export function bpsMul(amount: bigint, bps: bigint): bigint {
  return mulDiv(amount, bps, 10_000n);
}

export function toQ64(numerator: bigint, denominator: bigint): bigint {
  return mulDiv(numerator, Q64, denominator);
}

export function mulQ64(a: bigint, b: bigint): bigint {
  return mulDiv(a, b, Q64);
}

export function q64ToDecimal(q: bigint, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0) {
    throw new Error('q64ToDecimal: decimals must be a non-negative integer');
  }

  const sign = q < 0n ? '-' : '';
  const abs = q < 0n ? -q : q;

  const integer = abs >> 64n;
  if (decimals === 0) return `${sign}${integer}`;

  const fracMask = Q64 - 1n;
  const frac = abs & fracMask;

  const scale = 10n ** BigInt(decimals);
  const fracDec = mulDiv(frac, scale, Q64);
  const fracStr = fracDec.toString().padStart(decimals, '0');

  return `${sign}${integer}.${fracStr}`;
}

