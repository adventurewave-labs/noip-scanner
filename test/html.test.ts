import { describe, expect, it } from 'vitest';
import { renderHtml } from '../src/report/html.js';
import { ingestNetinspect } from '../src/report/netinspect.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, snap } from './helpers.js';

const NOW = new Date('2026-09-26T00:00:00Z');
const demo = () => buildReport(loadDemoSnapshot(), 'demo', { now: NOW });

describe('HTML report', () => {
  it('is a single self-contained document with no scripts or external assets', () => {
    const h = renderHtml(demo());
    expect(h.startsWith('<!doctype html>')).toBe(true);
    expect(h).not.toMatch(/<script|<link|src=|@import|url\(/i);
    expect(h).toContain('DEMO DATA');
    expect(h).toContain('prefers-color-scheme:dark');
    expect(h).toContain('@media print');
  });

  it('includes every finding with evidence identical to JSON (after escaping)', () => {
    const r = demo();
    const h = renderHtml(r);
    const esc = (x: string) => x.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    for (const f of r.findings) expect(h).toContain(`<code>${esc(f.evidence)}</code>`);
    expect(h).toContain('reference mappings, not an attestation');
  });

  it('escapes hostile resource names and evidence (no HTML injection)', () => {
    const evil = hardenedPod('app', '<img src=x onerror=alert(1)>', (p) => (p.spec!.hostPID = true));
    const h = renderHtml(buildReport(snap({ pods: [evil] }), 'live', { now: NOW }));
    expect(h).not.toContain('<img');
    expect(h).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('renders optional sections: manifests banner + file:line, suppressed, warnings, explanation, network, minSeverity', () => {
    const r = buildReport(loadDemoSnapshot(), 'manifests', {
      now: NOW,
      minSeverity: 'high',
      suppressions: [
        { check: 'NOIP-POD-004', reason: 'host network needed for metrics', owner: 'sre', expires: '2099-01-01' },
        { check: 'NOIP-POD-003', reason: 'expired exception for a legacy pod', owner: 'sre', expires: '2000-01-01' },
      ],
    });
    r.findings[0]!.resource.source = { file: 'k8s/app.yaml', line: 7 };
    r.explanation = { summary: 'Fix <b>this</b> first', priorities: [{ findingId: r.findings[0]!.id, why: 'root', fix: 'drop it' }], caveats: [] };
    r.network = ingestNetinspect(JSON.stringify({ checks: [{ name: 'dns', status: 'warn', detail: 'slow' }] }));
    const h = renderHtml(r);
    for (const s of ['OFFLINE MANIFEST SCAN', 'k8s/app.yaml:7', 'Suppressed (accepted risk)', 'Warnings', 'LLM-generated', 'Fix &lt;b&gt;this&lt;/b&gt; first', 'k8s-netinspect', 'Minimum severity']) {
      expect(h).toContain(s);
    }
  });

  it('says so when there are no findings', () => {
    expect(renderHtml(buildReport(snap(), 'live', { now: NOW }))).toContain('<p>No findings.</p>');
  });
});

describe('HTML report with sparse data', () => {
  it('handles missing context/platform/line, empty excludes, controls without findings and network detail', () => {
    const r = buildReport(snap({ context: undefined, serverVersion: { gitVersion: 'v1.30.0' } }), 'live', { now: NOW, includeSystemNamespaces: true });
    r.findings.push({ ...demo().findings[0]!, controls: [], resource: { kind: 'Pod', name: 'p', source: { file: 'a.yaml' } } });
    r.network = ingestNetinspect(JSON.stringify({ checks: [{ name: 'dns', status: 'pass' }] }));
    r.explanation = { summary: 's', priorities: [], caveats: [] };
    const h = renderHtml(r);
    expect(h).toContain('<title>NOIP posture report: live</title>');
    expect(h).toContain('<dd>none</dd>');
    expect(h).toContain('<span class="muted">a.yaml</span>');
    expect(h).toContain('<td>—</td>');
  });
});
