import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // The real-engine suite scans every fixture × preset.
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
