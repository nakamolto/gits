import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const rootDir = fileURLToPath(new URL('.', import.meta.url));
const srcDir = path.join(rootDir, 'src');
const testDir = path.join(rootDir, 'test');

function isGhostSource(importer: string | undefined): boolean {
  if (!importer) return false;
  return importer.startsWith(srcDir) || importer.startsWith(testDir);
}

export default defineConfig({
  plugins: [
    {
      name: 'ghost-resolve-js-to-ts',
      enforce: 'pre',
      async resolveId(source: string, importer: string | undefined) {
        // Only rewrite our own NodeNext-style relative imports.
        // Do NOT touch dependencies like @gits-protocol/sdk, which legitimately import `.js` files.
        if (!isGhostSource(importer)) return null;
        if (!source.endsWith('.js')) return null;
        if (!source.startsWith('./') && !source.startsWith('../')) return null;

        const tsSource = `${source.slice(0, -3)}.ts`;
        const resolved = await this.resolve(tsSource, importer, { skipSelf: true });
        return resolved?.id ?? null;
      },
    },
  ],
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 10_000,
  },
});
