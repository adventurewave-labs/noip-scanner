import { describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { REFERENCES } from '../src/checks/references.js';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

describe('NSA/CISA and NIST SP 800-190 reference mappings', () => {
  it('cover every check, and NIST entries cite a section-4 risk', () => {
    for (const c of ALL_CHECKS) {
      const ref = REFERENCES[c.id];
      expect(ref, c.id).toBeDefined();
      expect(ref!.nsaCisa.length, c.id).toBeGreaterThan(0);
      for (const n of ref!.nist800190) expect(n).toMatch(/^4\.\d\.\d /);
    }
    expect(Object.keys(REFERENCES).sort()).toEqual(ALL_CHECKS.map((c) => c.id).sort());
  });

  it('flow into findings, markdown, HTML and SARIF, labelled as reference mappings', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    const f = r.findings.find((x) => x.checkId === 'NOIP-RBAC-002')!;
    expect(f.references).toEqual({ nsaCisa: ['Authentication and authorization'], nist800190: ['4.3.1 Unbounded administrative access'] });
    expect(r.mappingDisclaimer).toMatch(/NSA\/CISA and NIST SP 800-190 identifiers are reference mappings, not an attestation/);
    expect(renderMarkdown(r)).toContain('- References: NSA/CISA Authentication and authorization · NIST SP 800-190 4.3.1 Unbounded administrative access');
    expect(renderHtml(r)).toContain('NIST 800-190: 4.3.1 Unbounded administrative access');
    const rule = renderSarif(r).runs[0]!.tool.driver.rules!.find((x) => x.id === 'NOIP-RBAC-002')!;
    expect(rule.properties!.tags).toContain('NIST-800-190 4.3.1');
  });
});

describe('checks without reference mappings (e.g. future or third-party checks)', () => {
  it('omit references cleanly everywhere', () => {
    const custom = { id: 'NOIP-XYZ-001', title: 'Custom', severity: 'low' as const, category: 'Pod Security' as const, controls: [], remediation: 'r', run: () => [{ resource: { kind: 'Namespace', name: 'x' }, evidence: 'e' }] };
    const r = buildReport(loadDemoSnapshot(), 'demo', {}, [custom]);
    expect(r.findings[0]!.references).toBeUndefined();
    expect(renderMarkdown(r)).not.toContain('- References:');
    const rule = renderSarif(r, [custom]).runs[0]!.tool.driver.rules![0]!;
    expect(rule.properties!.references).toBeUndefined();
    r.findings[0]!.references = { nsaCisa: [], nist800190: [] };
    expect(renderMarkdown(r)).toContain('- References: NSA/CISA — · NIST SP 800-190 —');
    expect(renderHtml(r)).toContain('NSA/CISA: —');
  });
});
