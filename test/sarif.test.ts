import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { snap } from './helpers.js';

// Official OASIS SARIF 2.1.0 schema (errata01), vendored from oasis-tcs/sarif-spec.
const schema = JSON.parse(readFileSync(new URL('../schemas/vendor/sarif-schema-2.1.0.json', import.meta.url), 'utf8'));
// ajv-draft-04 is CommonJS; require() sidesteps NodeNext default-import interop.
type AjvCtor = new (o: object) => { compile: (s: object) => ((d: unknown) => boolean) & { errors?: unknown[] | null } };
const Ajv = createRequire(import.meta.url)('ajv-draft-04') as AjvCtor;
const validate = new Ajv({ allErrors: true, strict: false, validateFormats: false }).compile(schema);
const demo = () => buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-01-01T00:00:00Z') });

describe('SARIF output', () => {
  it('validates against the official SARIF 2.1.0 schema', () => {
    const log = renderSarif(demo());
    expect(validate(log), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
  });

  it('has one rule per check run and one result per finding, with stable fingerprints', () => {
    const r = demo();
    const run = renderSarif(r).runs[0]!;
    expect(run.tool.driver.rules!.map((x) => x.id)).toEqual(r.provenance.checksRun);
    expect(run.results).toHaveLength(r.findings.length);
    const first = run.results![0]!;
    expect(first.partialFingerprints).toEqual({ 'noipFindingId/v1': r.findings[0]!.id });
    expect(run.tool.driver.rules![first.ruleIndex!]!.id).toBe(first.ruleId);
  });

  it('maps severities to SARIF levels and GitHub security-severity scores', () => {
    const run = renderSarif(demo()).runs[0]!;
    const byId = Object.fromEntries(run.tool.driver.rules!.map((x) => [x.id, x]));
    expect(byId['NOIP-POD-001']!.defaultConfiguration!.level).toBe('error');
    expect(byId['NOIP-POD-001']!.properties!['security-severity']).toBe('9.5');
    expect(byId['NOIP-POD-005']!.defaultConfiguration!.level).toBe('warning');
    expect(byId['NOIP-POD-008']!.defaultConfiguration!.level).toBe('note');
    expect(byId['NOIP-POD-001']!.name).toBe('PrivilegedContainer');
  });

  it('uses a pseudo-path for live resources and the real file/line for manifest resources', () => {
    const r = demo();
    r.findings[0]!.resource.source = { file: 'deploy/app.yaml', line: 12 };
    const [a, b] = renderSarif(r).runs[0]!.results!;
    expect(a!.locations![0]!.physicalLocation).toEqual({ artifactLocation: { uri: 'deploy/app.yaml' }, region: { startLine: 12 } });
    expect(b!.locations![0]!.physicalLocation!.artifactLocation!.uri).toMatch(/^k8s\//);
    expect(validate(renderSarif(r))).toBe(true);
  });

  it('is valid with zero findings', () => {
    const log = renderSarif(buildReport(snap(), 'live'));
    expect(log.runs[0]!.results).toEqual([]);
    expect(validate(log)).toBe(true);
  });
});
