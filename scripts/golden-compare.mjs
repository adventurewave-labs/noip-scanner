// Usage: node scripts/golden-compare.mjs report.json [--source live|manifests]
// Asserts the live kind scan found exactly the seeded misconfigurations and nothing in the clean namespace (PRD R-4).
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const reportPath = args[0];
const sourceIdx = args.indexOf('--source');
const expectedSource = sourceIdx >= 0 ? args[sourceIdx + 1] : 'live';
const goldenPath = new URL('../test/golden/kind-findings.json', import.meta.url);
const raw = readFileSync(reportPath, 'utf8');
const report = JSON.parse(raw);
const golden = JSON.parse(readFileSync(goldenPath, 'utf8'));
const errors = [];

const inScope = (r) =>
  r.namespace ? r.namespace.startsWith(golden.scope.namespacePrefix) : r.name.startsWith(golden.scope.clusterScopedNamePrefix);
const actual = new Set(report.findings.filter((f) => inScope(f.resource)).map((f) => f.id));
const expected = new Set(golden.expectedFindingIds);

if (report.source !== expectedSource) errors.push(`report.source is "${report.source}", expected "${expectedSource}"`);
for (const id of expected) if (!actual.has(id)) errors.push(`MISSING  ${id}`);
for (const id of actual) if (!expected.has(id)) errors.push(`UNEXPECTED ${id}`);

const clean = report.findings.filter((f) => f.resource.namespace === golden.cleanNamespace || f.resource.name === golden.cleanNamespace);
for (const f of clean) errors.push(`FALSE POSITIVE in clean namespace: ${f.id}`);

const failedControls = new Set(report.controls.filter((c) => c.status === 'fail').map((c) => c.id));
for (const c of golden.expectedFailedControls) if (!failedControls.has(c)) errors.push(`control ${c} expected to fail`);

if (raw.includes(golden.seededSecretValue)) errors.push('seeded secret VALUE appears in the report');

console.log(`seeded findings: expected ${expected.size}, matched ${[...expected].filter((i) => actual.has(i)).length}; clean-namespace findings: ${clean.length}`);
if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
console.log('golden: PASS');
