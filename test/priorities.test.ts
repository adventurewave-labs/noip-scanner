import { describe, expect, it } from 'vitest';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { executiveSummary } from '../src/report/priorities.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { snap } from './helpers.js';

describe('executive summary', () => {
  const r = buildReport(loadDemoSnapshot(), 'demo');
  const ex = executiveSummary(r);

  it('ranks by severity, then blast radius, then reach, deterministically', () => {
    expect(ex.priorities.map((p) => `${p.checkId}:${p.scope}:${p.resources}`)).toEqual([
      'NOIP-POD-001:workload:1',
      'NOIP-POD-002:workload:1',
      'NOIP-RBAC-002:cluster:1',
      'NOIP-NET-001:namespace:3',
      'NOIP-POD-006:workload:3',
    ]);
    expect(executiveSummary(r)).toEqual(ex);
  });

  it('counts quick wins vs design decisions and dedupes samples', () => {
    expect(ex.quickWins + ex.needsDesign).toBe(r.findings.length);
    expect(ex.quickWins).toBe(r.findings.filter((f) => f.fix).length);
    for (const p of ex.priorities) expect(new Set(p.sample).size).toBe(p.sample.length);
    expect(ex.headline).toBe(`Score 12/100. 25 finding(s) (2 critical, 9 high) from 14 of 15 checks; ${ex.quickWins} have a deterministic fix.`);
  });

  it('renders in markdown and HTML and handles a clean cluster', () => {
    expect(renderMarkdown(r)).toContain('## Executive summary');
    expect(renderMarkdown(r)).toContain('1. **NOIP-POD-001: Privileged container**');
    expect(renderHtml(r)).toContain('<h2>Executive summary</h2>');
    const clean = buildReport(snap(), 'live');
    expect(executiveSummary(clean)).toEqual({ headline: 'No findings across 15 checks. Score 100/100.', priorities: [], quickWins: 0, needsDesign: 0 });
    expect(renderMarkdown(clean)).not.toContain('Fix these first');
  });

  it('honours the top-N limit', () => {
    expect(executiveSummary(r, 2).priorities).toHaveLength(2);
  });
});
