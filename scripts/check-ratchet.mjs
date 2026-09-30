// Fails if coverage-thresholds.json lowers any threshold relative to the base ref (PRD R-9: the threshold never decreases).
// Usage: node scripts/check-ratchet.mjs origin/main
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const base = process.argv[2] ?? 'origin/main';
const current = JSON.parse(readFileSync(new URL('../coverage-thresholds.json', import.meta.url), 'utf8'));
let previous;
try {
  previous = JSON.parse(execFileSync('git', ['show', `${base}:coverage-thresholds.json`], { stdio: ['ignore', 'pipe', 'ignore'] }).toString());
} catch {
  console.log(`ratchet: no coverage-thresholds.json on ${base}; nothing to compare`);
  process.exit(0);
}
const lowered = Object.keys(previous).filter((k) => (current[k] ?? 0) < previous[k]);
for (const k of Object.keys(previous)) console.log(`${k.padEnd(10)} ${String(previous[k]).padStart(5)} -> ${String(current[k]).padStart(5)}`);
if (lowered.length) {
  console.error(`ratchet: thresholds lowered for ${lowered.join(', ')} — raise coverage instead.`);
  process.exit(1);
}
console.log('ratchet: OK');
