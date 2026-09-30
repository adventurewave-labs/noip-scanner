import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { renderOscal, token, uuidv5 } from '../src/report/oscal.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { snap } from './helpers.js';

// ajv (draft-07) and ajv-formats are CommonJS; require() sidesteps NodeNext default-import interop.
const req = createRequire(import.meta.url);
type Validator = ((d: unknown) => boolean) & { errors?: unknown[] | null };
const Ajv = req('ajv') as new (o: object) => { compile: (s: object) => Validator };
const addFormats = req('ajv-formats') as (a: unknown) => void;
const ajv = new Ajv({ allErrors: true, strict: false, unicodeRegExp: true });
addFormats(ajv);
const validate = ajv.compile(JSON.parse(readFileSync('schemas/vendor/oscal-assessment-results-1.2.3.schema.json', 'utf8')));
const valid = (doc: unknown) => {
  const ok = validate(doc);
  if (!ok) console.error(JSON.stringify(validate.errors?.slice(0, 5), null, 1));
  return ok;
};

type AR = { 'assessment-results': { uuid: string; results: Array<{ observations?: Array<{ uuid: string }>; findings: Array<{ title: string; target: { status: { state: string } }; 'related-observations'?: unknown[] }> }>; 'import-ap': { href: string }; 'back-matter': { resources: Array<{ uuid: string }> } } };

describe('OSCAL assessment results', () => {
  const now = new Date('2026-09-26T12:00:00Z');
  it('validates against the official OSCAL 1.2.3 schema and maps controls to findings', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { now });
    const doc = renderOscal(r) as AR;
    expect(valid(doc)).toBe(true);
    const res = doc['assessment-results'].results[0]!;
    expect(res.observations).toHaveLength(r.findings.length);
    expect(res.findings).toHaveLength(r.controls.length);
    const failed = r.controls.filter((c) => c.status === 'fail').length;
    expect(res.findings.filter((f) => f.target.status.state === 'not-satisfied')).toHaveLength(failed);
    // import-ap points at a back-matter resource that states there is no assessment plan
    expect(doc['assessment-results']['import-ap'].href).toBe(`#${doc['assessment-results']['back-matter'].resources[0]!.uuid}`);
  });

  it('is deterministic and valid for clean scans and suppressed findings', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { now });
    expect(JSON.stringify(renderOscal(r))).toBe(JSON.stringify(renderOscal(r)));
    const clean = renderOscal(buildReport(snap(), 'live', { now })) as AR;
    expect(valid(clean)).toBe(true);
    const id = r.findings.find((f) => f.controls.length)!.id;
    const sup = buildReport(loadDemoSnapshot(), 'demo', { now, suppressions: [{ id, reason: 'accepted', owner: 'sre', expires: '2099-01-01' }] });
    expect(valid(renderOscal(sup))).toBe(true);
  });

  it('produces RFC 4122 v5 UUIDs and NCName tokens', () => {
    expect(uuidv5('x')).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    // RFC 4122 appendix-style check against a known vector (DNS namespace, "python.org")
    expect(uuidv5('python.org', '6ba7b810-9dad-11d1-80b4-00c04fd430c8')).toBe('886313e1-3b8a-5372-9b90-0c9aee199e5d');
    expect(token('CIS-5.2.1_obj')).toBe('cis-5.2.1_obj');
    expect(token('1 bad/id')).toBe('_1-bad-id');
  });
});

describe('noip scan / render -o oscal', () => {
  let out = '';
  beforeEach(() => {
    out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((s) => ((out += String(s)), true));
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });
  it('emits a valid document from a scan and from a saved report', async () => {
    await main(['node', 'noip', 'scan', '--demo', '-o', 'oscal']);
    expect(valid(JSON.parse(out))).toBe(true);
    const f = join(mkdtempSync(join(tmpdir(), 'noip-oscal-')), 'r.json');
    await main(['node', 'noip', 'scan', '--demo', '--out', f]);
    out = '';
    await main(['node', 'noip', 'render', f, '-o', 'oscal']);
    expect(valid(JSON.parse(out))).toBe(true);
  });
});
