import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsPlugin from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { applySuppressions, globToRegExp, IgnoreFileError, loadIgnoreFile, type Suppression } from '../src/suppressions.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const base = { reason: 'node-exporter needs host networking to scrape node metrics', owner: 'sre@example.com', expires: '2026-12-31' };
const demo = (suppressions?: Suppression[]) => buildReport(loadDemoSnapshot(), 'demo', { now: NOW, suppressions });

const ajv = new Ajv2020({ allErrors: true, strict: true });
const addFormats = ((addFormatsPlugin as unknown as { default?: unknown }).default ?? addFormatsPlugin) as unknown as (a: Ajv2020) => void;
addFormats(ajv);
const validateReport = ajv.compile(JSON.parse(readFileSync(new URL('../schemas/report.schema.json', import.meta.url), 'utf8')));
type AjvCtor = new (o: object) => { compile: (s: object) => (d: unknown) => boolean };
const validateSarif = new (createRequire(import.meta.url)('ajv-draft-04') as AjvCtor)({ strict: false, validateFormats: false }).compile(
  JSON.parse(readFileSync(new URL('../schemas/vendor/sarif-schema-2.1.0.json', import.meta.url), 'utf8')),
);

describe('globToRegExp', () => {
  it('treats * as one segment and ** as many', () => {
    expect(globToRegExp('DaemonSet/monitoring/*').test('DaemonSet/monitoring/node-exporter')).toBe(true);
    expect(globToRegExp('DaemonSet/*').test('DaemonSet/monitoring/node-exporter')).toBe(false);
    expect(globToRegExp('DaemonSet/**').test('DaemonSet/monitoring/node-exporter/c')).toBe(true);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
  });
});

describe('applying suppressions', () => {
  it('moves matched findings to suppressed with the accountability fields', () => {
    const r = demo([{ ...base, check: 'NOIP-POD-004', resource: 'DaemonSet/monitoring/*' }]);
    expect(r.findings.some((f) => f.id === 'NOIP-POD-004:DaemonSet/monitoring/node-exporter')).toBe(false);
    expect(r.suppressed).toEqual([
      { finding: expect.objectContaining({ id: 'NOIP-POD-004:DaemonSet/monitoring/node-exporter' }), suppression: { ...base, rule: 'NOIP-POD-004 DaemonSet/monitoring/*' } },
    ]);
    expect(r.summary.suppressed).toBe(1);
    expect(r.summary.findings).toBe(demo().summary.findings - 1);
    expect(r.warnings).toBeUndefined();
  });

  it('suppresses by exact finding id, and by check alone', () => {
    const id = 'NOIP-POD-001:Pod/ci/debug-shell/shell';
    expect(demo([{ ...base, id }]).suppressed!.map((x) => x.finding.id)).toEqual([id]);
    const byCheck = demo([{ ...base, check: 'NOIP-NET-001' }]);
    expect(byCheck.findings.some((f) => f.checkId === 'NOIP-NET-001')).toBe(false);
    expect(byCheck.controls.find((c) => c.id === 'CIS-5.3.2')!.status).toBe('pass');
  });

  it('ignores expired suppressions and warns; warns about stale ones', () => {
    const r = demo([
      { ...base, check: 'NOIP-POD-004', expires: '2026-01-01' },
      { ...base, id: 'NOIP-POD-001:Pod/nowhere/x/y' },
    ]);
    expect(r.summary.suppressed).toBe(0);
    expect(r.warnings).toEqual([
      'suppression expired on 2026-01-01 (owner sre@example.com): NOIP-POD-004; its findings are active again',
      'suppression matched no findings (stale?): NOIP-POD-001:Pod/nowhere/x/y',
    ]);
  });

  it('expiry date is inclusive', () => {
    expect(applySuppressions([], [{ ...base, check: 'NOIP-POD-004', expires: '2026-09-26' }], NOW).warnings).toEqual([expect.stringMatching(/matched no findings/)]);
  });

  it('keeps the report, markdown and SARIF valid and honest', () => {
    const r = demo([{ ...base, check: 'NOIP-POD-004' }, { ...base, check: 'NOIP-POD-003', expires: '2020-01-01' }]);
    expect(validateReport(r), JSON.stringify(validateReport.errors)).toBe(true);
    const md = renderMarkdown(r);
    expect(md).toContain('## Suppressed (accepted risk)');
    expect(md).toContain('sre@example.com');
    expect(md).toContain('## Warnings');
    const sarif = renderSarif(r);
    const sup = sarif.runs[0]!.results!.filter((x) => x.suppressions);
    expect(sup).toHaveLength(1);
    expect(sup[0]!.suppressions![0]).toMatchObject({ kind: 'external', status: 'accepted' });
    expect(validateSarif(sarif)).toBe(true);
  });
});

describe('ignore file', () => {
  const write = (body: string) => {
    const f = join(mkdtempSync(join(tmpdir(), 'noip-ign-')), '.noip-ignore.yaml');
    writeFileSync(f, body);
    return f;
  };

  it('parses a valid file (YAML dates are accepted)', () => {
    const f = write(`suppressions:\n  - check: NOIP-POD-004\n    resource: "DaemonSet/monitoring/*"\n    reason: ${base.reason}\n    owner: ${base.owner}\n    expires: 2026-12-31\n`);
    expect(loadIgnoreFile(f)).toEqual([{ ...base, check: 'NOIP-POD-004', resource: 'DaemonSet/monitoring/*' }]);
  });

  it('rejects entries without accountability or with ambiguous targets', () => {
    expect(() => loadIgnoreFile(write('suppressions:\n  - check: NOIP-POD-004\n    reason: short\n    owner: me\n    expires: 2026-12-31\n'))).toThrow(/reason must explain/);
    expect(() => loadIgnoreFile(write(`suppressions:\n  - check: NOIP-POD-004\n    reason: ${base.reason}\n    owner: me\n`))).toThrow(/expires/);
    expect(() => loadIgnoreFile(write(`suppressions:\n  - id: x\n    check: NOIP-POD-004\n    reason: ${base.reason}\n    owner: me\n    expires: 2026-12-31\n`))).toThrow(/exactly one/);
    expect(() => loadIgnoreFile(write(`suppressions:\n  - id: x\n    resource: "a/*"\n    reason: ${base.reason}\n    owner: me\n    expires: 2026-12-31\n`))).toThrow(/only applies together/);
    expect(() => loadIgnoreFile(write('suppressions: [\n'))).toThrow(IgnoreFileError);
    expect(() => loadIgnoreFile(write('nope: 1\n'))).toThrow(IgnoreFileError);
  });

  it('an explicit missing path is an error; a missing default is not; an empty file is fine', () => {
    expect(() => loadIgnoreFile('/nonexistent/.noip-ignore.yaml')).toThrow(/not found/);
    expect(loadIgnoreFile()).toEqual([]);
    expect(loadIgnoreFile(write(''))).toEqual([]);
  });
});
