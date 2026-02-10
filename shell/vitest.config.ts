import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@gits-protocol/sdk': path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../sdk/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
  },
});
