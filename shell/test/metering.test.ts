import { describe, expect, it } from 'vitest';

import { countSU } from '../src/sessions/metering.js';

describe('metering', () => {
  it('counts SU as number of v_i == 1 intervals', () => {
    expect(countSU([{ vi: 0 }, { vi: 1 }, { vi: 1 }, { vi: 0 }])).toEqual(2);
  });
});

