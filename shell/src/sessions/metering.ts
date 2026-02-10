import type { IntervalRow } from '../storage/intervals.js';

export function countSU(intervals: Array<Pick<IntervalRow, 'vi'>>): number {
  let su = 0;
  for (const it of intervals) su += it.vi ? 1 : 0;
  return su;
}

