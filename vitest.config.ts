import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

// Thresholds live in coverage-thresholds.json so CI can enforce the ratchet
// (a PR may raise them, never lower them). See scripts/check-ratchet.mjs.
const thresholds = JSON.parse(readFileSync(new URL('./coverage-thresholds.json', import.meta.url), 'utf8'));

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    env: { NOIP_GIT_SHA: 'test-sha', NOIP_LOG_LEVEL: 'error' },
    coverage: {
      provider: 'v8',
      // R-9: coverage is measured on the retained core only.
      include: ['src/checks/**', 'src/scan.ts', 'src/manifests.ts', 'src/report/**', 'src/llm/**', 'src/k8s/**'],
      reporter: ['text-summary', 'json-summary'],
      thresholds,
    },
  },
});
