import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { renderHtml } from '../src/report/html.js';
import { importSarif } from '../src/report/import-sarif.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const file = new URL('./fixtures/sarif/trivy.sarif', import.meta.url).pathname;
const raw = readFileSync(file, 'utf8');
type AjvCtor = new (o: object) => { compile: (s: object) => (d: unknown) => boolean };
const validateSarif = new (createRequire(import.meta.url)('ajv-draft-04') as AjvCtor)({ strict: false, validateFormats: false }).compile(
  JSON.parse(readFileSync(new URL('../schemas/vendor/sarif-schema-2.1.0.json', import.meta.url), 'utf8')),
);

describe('--import-sarif', () => {
  it('maps runs, severities (security-severity, then level) and locations; drops tool-suppressed results', () => {
    const [trivy, checkov] = importSarif(raw, 'trivy.sarif');
    expect(trivy).toMatchObject({ tool: 'Trivy', version: '0.58.0', inputFile: 'trivy.sarif', inputSha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(trivy!.results).toEqual([
      { ruleId: 'KSV-0014', severity: 'high', message: "Container 'api' should set readOnlyRootFilesystem", location: { uri: 'k8s/api.yaml', line: 12 } },
      { ruleId: 'CVE-2024-0001', severity: 'critical', message: 'openssl 3.0.1 is affected', location: { uri: 'registry.example.com/api:1.0' } },
      { ruleId: 'KSV-0011', severity: 'low', message: 'CPU limit not set' },
    ]);
    expect(checkov).toMatchObject({ tool: 'Checkov', version: '3.2.0', results: [{ ruleId: 'CKV_K8S_20', severity: 'medium' }] });
  });

  it('never changes NOIP score or controls, and renders in every format', () => {
    const base = buildReport(loadDemoSnapshot(), 'demo');
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.imported = importSarif(raw, 'trivy.sarif');
    expect(r.summary).toEqual(base.summary);
    expect(renderMarkdown(r)).toContain('## Imported: Trivy 0.58.0');
    expect(renderHtml(r)).toContain('Imported: Checkov 3.2.0');
    const sarif = renderSarif(r);
    expect(sarif.runs.map((x) => x.tool.driver.name)).toEqual(['noip', 'Trivy', 'Checkov']);
    expect(validateSarif(sarif)).toBe(true);
  });

  it('rejects non-JSON and non-SARIF input clearly', () => {
    expect(() => importSarif('{', 'x.sarif')).toThrow(/not valid JSON/);
    expect(() => importSarif('{"version":"2.0.0","runs":[]}', 'x.sarif')).toThrow(/not SARIF 2.1.0/);
  });

  it('handles an empty run and numeric security-severity', () => {
    const [run] = importSarif(JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'X' } } }] }), 'e.sarif');
    expect(run!.results).toEqual([]);
    const [n] = importSarif(JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Y' } }, results: [{ message: {}, properties: { 'security-severity': 4.5 } }] }] }), 'n.sarif');
    expect(n!.results).toEqual([{ ruleId: 'unknown', severity: 'medium', message: '' }]);
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.imported = [run!];
    expect(renderMarkdown(r)).toContain('No results.');
    expect(renderHtml(r)).toContain('<p>No results.</p>');
  });
});
