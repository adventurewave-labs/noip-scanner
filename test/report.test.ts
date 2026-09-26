import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsPlugin from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { mdSafe, renderMarkdown } from '../src/report/markdown.js';
import { ingestNetinspect } from '../src/report/netinspect.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { snap } from './helpers.js';

const ajv = new Ajv2020({ allErrors: true, strict: true });
// ajv-formats is CJS; under NodeNext its default export arrives wrapped.
const addFormats = ((addFormatsPlugin as unknown as { default?: typeof addFormatsPlugin }).default ?? addFormatsPlugin) as unknown as (a: Ajv2020) => void;
addFormats(ajv);
const validate = ajv.compile(JSON.parse(readFileSync(new URL('../schemas/report.schema.json', import.meta.url), 'utf8')));
const demo = () => buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-01-01T00:00:00Z') });

describe('report schema (R-10)', () => {
  it('validates with imported SARIF runs', async () => {
    const { importSarif } = await import('../src/report/import-sarif.js');
    const r = demo();
    r.imported = importSarif(readFileSync(new URL('./fixtures/sarif/trivy.sarif', import.meta.url), 'utf8'), 'trivy.sarif');
    expect(validate(r), JSON.stringify(validate.errors)).toBe(true);
  });

  it('validates the demo report', () => {
    expect(validate(demo()), JSON.stringify(validate.errors)).toBe(true);
  });

  it('validates with network and explanation sections, including explanation: null', () => {
    const r = demo();
    r.network = ingestNetinspect(JSON.stringify({ tool: 'k8s-netinspect', cni: 'calico', checks: [{ name: 'pod-to-pod', status: 'pass' }] }));
    r.explanation = { summary: 's', priorities: [{ findingId: r.findings[0]!.id, why: 'w', fix: 'f' }], caveats: [] };
    expect(validate(r), JSON.stringify(validate.errors)).toBe(true);
    r.explanation = null;
    expect(validate(r)).toBe(true);
  });

  it('rejects a report without source or provenance', () => {
    const r = demo() as unknown as Record<string, unknown>;
    delete r.source;
    expect(validate(r)).toBe(false);
  });

  it('carries provenance: scanner version + sha, /version server version, timestamp, checks run', () => {
    const r = demo();
    expect(r.provenance.scanner).toEqual({ name: 'noip', version: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version, gitSha: 'test-sha' });
    expect(r.provenance.cluster.serverVersion).toBe('v1.31.4');
    expect(r.provenance.scannedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(r.provenance.checksRun).toHaveLength(15);
    expect(r.mappingDisclaimer).toMatch(/reference mappings, not an attestation/);
  });

  it('scores 100 for a clean snapshot and counts each failed check once', () => {
    expect(buildReport(snap(), 'live').summary.score).toBe(100);
    expect(demo().summary.score).toBe(12);
  });
});

describe('markdown (R-7)', () => {
  it('has an Evidence line per finding identical to the JSON evidence', () => {
    const r = demo();
    const md = renderMarkdown(r);
    const lines = md.split('\n').filter((l) => l.startsWith('- Evidence: ')).map((l) => l.slice('- Evidence: '.length));
    // Evidence is escaped for Markdown (e.g. `<-` -> `&lt;-`) but renders identically to the JSON text.
    expect(lines).toEqual(r.findings.map((f) => mdSafe(f.evidence)));
  });

  it('labels demo data and renders optional sections', () => {
    const r = demo();
    r.network = ingestNetinspect(JSON.stringify({ checks: [{ name: 'dns', status: 'warn', detail: 'slow | 2s' }] }));
    r.explanation = { summary: 'Fix the privileged pod first.', priorities: [{ findingId: 'x', why: 'w', fix: 'f' }], caveats: ['advisory'] };
    const md = renderMarkdown(r);
    expect(md).toContain('DEMO DATA');
    expect(md).toContain('## Network (ingested from k8s-netinspect)');
    expect(md).toContain('slow \\| 2s');
    expect(md).toContain('Fix the privileged pod first.');
    r.explanation = null;
    expect(renderMarkdown(r)).toContain('LLM explanation requested but unavailable');
  });

  it('says so when there are no findings and omits the demo banner for live data', () => {
    const md = renderMarkdown(buildReport(snap(), 'live'));
    expect(md).toContain('No findings.');
    expect(md).not.toContain('DEMO DATA');
  });
});

describe('netinspect ingest (R-12)', () => {
  it('rejects invalid JSON and wrong shapes', () => {
    expect(() => ingestNetinspect('{nope')).toThrow(/not valid JSON/);
    expect(() => ingestNetinspect(JSON.stringify({ checks: [{ name: 'x', status: 'bad' }] }))).toThrow(/does not match/);
  });
  it('records a content hash of the input', () => {
    expect(ingestNetinspect('{"checks":[]}').inputSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
