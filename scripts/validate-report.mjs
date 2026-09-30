// Usage: node scripts/validate-report.mjs report.json   — validates against schemas/report.schema.json (PRD R-10).
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const schema = JSON.parse(readFileSync(new URL('../schemas/report.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
let failed = false;
for (const file of process.argv.slice(2)) {
  const ok = validate(JSON.parse(readFileSync(file, 'utf8')));
  console.log(`${ok ? 'valid  ' : 'INVALID'} ${file}`);
  if (!ok) {
    failed = true;
    for (const e of validate.errors ?? []) console.log(`  ${e.instancePath || '/'} ${e.message}`);
  }
}
process.exit(failed ? 1 : 0);
