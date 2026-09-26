// Supply-chain gate (roadmap #8). Writes a CycloneDX SBOM of the runtime dependency tree and fails on
// licenses outside the allowlist. Usage: node scripts/supply-chain.mjs [out=sbom.cdx.json]
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

// Permissive licenses acceptable for a tool distributed to clients. Anything else needs a deliberate exception.
const ALLOWED = new Set(['MIT', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'Unlicense', 'CC0-1.0', 'BlueOak-1.0.0', 'Python-2.0']);
// name@version -> reason. Keep empty unless reviewed.
const EXCEPTIONS = {};

const out = process.argv[2] ?? 'sbom.cdx.json';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const raw = execFileSync(npm, ['sbom', '--sbom-format', 'cyclonedx', '--omit', 'dev'], { maxBuffer: 64 * 1024 * 1024 }).toString();
const bom = JSON.parse(raw);
writeFileSync(out, JSON.stringify(bom, null, 2) + '\n');

const licensesOf = (c) =>
  (c.licenses ?? []).flatMap((l) => (l.expression ? l.expression.replace(/[()]/g, '').split(/\s+(?:OR|AND)\s+/) : [l.license?.id ?? l.license?.name ?? '']));
const problems = [];
for (const c of bom.components ?? []) {
  const key = `${c.name}@${c.version}`;
  if (EXCEPTIONS[key]) continue;
  const ls = licensesOf(c).filter(Boolean);
  // An OR expression is fine if any option is allowed; AND needs all. Treat single ids the same way.
  const expr = (c.licenses ?? []).find((l) => l.expression)?.expression ?? '';
  const ok = ls.length > 0 && (/\bAND\b/.test(expr) ? ls.every((l) => ALLOWED.has(l)) : ls.some((l) => ALLOWED.has(l)));
  if (!ok) problems.push(`${key}: ${ls.join(' / ') || 'no license declared'}`);
}
console.log(`sbom: ${bom.components?.length ?? 0} runtime components -> ${out} (CycloneDX ${bom.specVersion})`);
if (problems.length) {
  console.error(`license gate: ${problems.length} component(s) outside the allowlist:\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log('license gate: OK');
