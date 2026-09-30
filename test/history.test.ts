import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT, main } from '../src/cli.js';
import { buildHistory, isReport, loadHistory, renderHistoryHtml, renderHistoryMarkdown } from '../src/report/history.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import type { Report } from '../src/types.js';

function rep(at: string, score: number, patch: (r: Report) => void = () => {}): Report {
  const r = buildReport(loadDemoSnapshot(), 'demo', { now: new Date(at) });
  r.summary.score = score;
  patch(r);
  return r;
}

describe('buildHistory', () => {
  it('groups by source+context, sorts by time and computes deltas', () => {
    const h = buildHistory([
      { file: 'c.json', report: rep('2026-09-03T00:00:00Z', 70) },
      { file: 'a.json', report: rep('2026-09-01T00:00:00Z', 50) },
      { file: 'b.json', report: rep('2026-09-02T00:00:00Z', 65) },
      { file: 'p.json', report: rep('2026-09-01T00:00:00Z', 90, (r) => (r.provenance.cluster.context = 'prod')) },
      { file: 'm.json', report: rep('2026-09-01T00:00:00Z', 80, (r) => ((r.source = 'manifests'), delete r.provenance.cluster.context)) },
    ]);
    expect(h.targets.map((t) => t.key)).toEqual(['demo:demo-shop', 'demo:prod', 'manifests:default'].sort());
    const demo = h.targets.find((t) => t.key.startsWith('demo:') && t.context !== 'prod')!;
    expect(demo.points.map((p) => [p.file, p.score, p.delta])).toEqual([
      ['a.json', 50, null],
      ['b.json', 65, 15],
      ['c.json', 70, 5],
    ]);
    expect(demo.points[0]!.bySeverity).toEqual(expect.objectContaining({ critical: expect.any(Number) }));
    expect(h.targets.find((t) => t.key === 'manifests:default')!.context).toBeUndefined();
    expect(h.skipped).toEqual([]);
  });

  it('flags scope changes instead of reporting them as drift', () => {
    const h = buildHistory([
      { file: 'a', report: rep('2026-09-01T00:00:00Z', 50) },
      { file: 'b', report: rep('2026-09-02T00:00:00Z', 90, (r) => (r.provenance.minSeverity = 'high')) },
      { file: 'c', report: rep('2026-09-03T00:00:00Z', 95, (r) => ((r.provenance.minSeverity = 'high'), (r.provenance.checksRun = r.provenance.checksRun.slice(1)))) },
      { file: 'd', report: rep('2026-09-04T00:00:00Z', 96, (r) => ((r.provenance.minSeverity = 'high'), (r.provenance.checksRun = r.provenance.checksRun.slice(1)))) },
      { file: 'e', report: rep('2026-09-05T00:00:00Z', 40) },
    ]);
    const pts = h.targets[0]!.points;
    expect(pts.map((p) => [p.delta, p.scopeChanged])).toEqual([
      [null, undefined],
      [null, ['minSeverity']],
      [null, ['checks']],
      [1, undefined],
      [null, ['checks', 'minSeverity']],
    ]);
    const md = renderHistoryMarkdown(h);
    expect(md).toContain('not comparable: severity filter changed');
    expect(md).toContain('not comparable: check set changed; severity filter changed');
    expect(renderHistoryMarkdown(h, 'es')).toContain('no comparable: cambió el filtro de severidad');
  });

  it('skips non-reports, invalid timestamps and duplicates, and tolerates sparse legacy fields', () => {
    const legacy = rep('2026-09-02T00:00:00Z', 60) as unknown as { summary: Record<string, unknown>; provenance: Record<string, unknown> };
    delete legacy.summary.suppressed;
    delete legacy.summary.bySeverity;
    delete legacy.provenance.scanner;
    delete legacy.provenance.checksRun;
    const h = buildHistory([
      { file: 'x', report: { hello: 1 } },
      { file: 'n', report: null },
      { file: 't', report: rep('2026-09-01T00:00:00Z', 50, (r) => (r.provenance.scannedAt = 'yesterday')) },
      { file: 'a', report: rep('2026-09-01T00:00:00Z', 50) },
      { file: 'a-copy', report: rep('2026-09-01T00:00:00Z', 50) },
      { file: 'l', report: legacy },
    ]);
    expect(h.skipped.map((s) => s.file)).toEqual(['x', 'n', 't', 'a-copy']);
    const last = h.targets[0]!.points[1]!;
    expect(last).toMatchObject({ suppressed: 0, scannerVersion: 'unknown', gitSha: 'unknown', bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, scopeChanged: ['checks'] });
    expect(isReport(undefined)).toBe(false);
  });
});

describe('loadHistory', () => {
  it('reads files and directories recursively; skips invalid JSON but not unrelated files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-hist-'));
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'a.json'), JSON.stringify(rep('2026-09-01T00:00:00Z', 50)));
    writeFileSync(join(dir, 'sub', 'b.json'), JSON.stringify(rep('2026-09-02T00:00:00Z', 60)));
    writeFileSync(join(dir, 'notes.txt'), 'ignored');
    writeFileSync(join(dir, 'broken.json'), '{');
    const explicit = join(mkdtempSync(join(tmpdir(), 'noip-hist-')), 'report.out');
    writeFileSync(explicit, JSON.stringify(rep('2026-09-03T00:00:00Z', 75)));
    const h = loadHistory([dir, explicit]);
    expect(h.targets[0]!.points.map((p) => p.score)).toEqual([50, 60, 75]);
    expect(h.skipped).toEqual([{ file: join(dir, 'broken.json'), reason: 'not valid JSON' }]);
  });
});

describe('history renderers', () => {
  const h = buildHistory([
    { file: 'a', report: rep('2026-09-01T00:00:00Z', 40) },
    { file: 'b', report: rep('2026-09-10T12:00:00.123Z', 72) },
    { file: 'p', report: rep('2026-09-05T00:00:00Z', 88, (r) => (r.provenance.cluster.context = 'prod<script>|x')) },
    { file: 'bad<b>|.json', report: {} },
  ]);

  it('markdown: trend line, table and escaped untrusted text', () => {
    const md = renderHistoryMarkdown(h);
    expect(md).toMatch(/^# NOIP posture history/);
    expect(md).toContain('2 scan(s) from 2026-09-01 to 2026-09-10. Score 40 → 72 (+32); best 72, worst 40.');
    expect(md).toContain('| 2026-09-10 12:00:00 UTC | 72 | +32 |');
    expect(md).toContain('context prod&lt;script&gt;\\|x');
    expect(md).toContain('- bad&lt;b&gt;\\|.json: not a NOIP report');
    expect(renderHistoryMarkdown({ targets: [], skipped: [] })).toContain('No NOIP reports found.');
    expect(renderHistoryMarkdown(h, 'es')).toContain('# Historial de postura NOIP');
    const down = buildHistory([
      { file: 'a', report: rep('2026-09-01T00:00:00Z', 80) },
      { file: 'b', report: rep('2026-09-02T00:00:00Z', 60) },
    ]);
    expect(renderHistoryMarkdown(down)).toContain('Score 80 → 60 (-20)');
  });

  it('html: script-free SVG chart with tooltips, a table view and escaping', () => {
    const html = renderHistoryHtml(h);
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain('prod&lt;script&gt;|x');
    expect(html).toContain('<path class="line"');
    expect((html.match(/<circle class="dot"/g) ?? []).length).toBe(3);
    expect(html).toContain('<title>2026-09-10 12:00:00 UTC: score 72,');
    expect(html).toContain('role="img" aria-label="Posture score over time for Target: demo · context demo-shop (0–100)"');
    expect(html).toContain('<table>');
    expect(html).toContain('--series-1:#2a78d6');
    expect(html).toContain('--series-1:#3987e5');
    expect(html).toContain('<code>bad&lt;b&gt;|.json</code>');
    // single-point series: no line, centred marker
    const single = html.split('<section>').find((s) => s.includes('prod'))!;
    expect(single).not.toContain('class="line"');
    expect(single).toContain('text-anchor="middle"');
  });

  it('html: same-timestamp points fall back to even spacing; scores clamp to the 0–100 axis', () => {
    const same = buildHistory([
      { file: 'a', report: rep('2026-09-01T00:00:00Z', 10) },
      { file: 'b', report: rep('2026-09-01T00:00:00Z', 140) },
    ]);
    const html = renderHistoryHtml(same, 'es');
    expect(html).toContain('<html lang="es">');
    expect(html).toMatch(/d="M36\.0,[\d.]+L600\.0,14\.0"/);
    expect(renderHistoryHtml({ targets: [], skipped: [] })).toContain('No NOIP reports found.');
  });
});

describe('noip history subcommand', () => {
  let out = '';
  let err = '';
  beforeEach(() => {
    out = '';
    err = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((s) => ((out += String(s)), true));
    vi.spyOn(process.stderr, 'write').mockImplementation((s) => ((err += String(s)), true));
  });
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('renders md, json and html (to a file) and fails when nothing usable is found', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-hist-cli-'));
    writeFileSync(join(dir, 'a.json'), JSON.stringify(rep('2026-09-01T00:00:00Z', 50)));
    writeFileSync(join(dir, 'b.json'), JSON.stringify(rep('2026-09-02T00:00:00Z', 60)));
    await main(['node', 'noip', 'history', dir]);
    expect(out).toContain('Score 50 → 60 (+10)');
    expect(err).toContain('history: 2 report(s) across 1 target(s)');
    out = '';
    await main(['node', 'noip', 'history', dir, '-o', 'json']);
    expect(JSON.parse(out).targets[0].points).toHaveLength(2);
    const f = join(dir, 'h.html');
    await main(['node', 'noip', 'history', join(dir, 'a.json'), '-o', 'html', '--lang', 'es', '--out', f]);
    expect(readFileSync(f, 'utf8')).toContain('Historial de postura NOIP');
    expect(process.exitCode).toBeUndefined();
    const empty = mkdtempSync(join(tmpdir(), 'noip-hist-cli-'));
    writeFileSync(join(empty, 'x.json'), '{"hello":1}');
    await main(['node', 'noip', 'history', empty]);
    expect(err).toContain('1 file(s) skipped');
    expect(process.exitCode).toBe(EXIT.ERROR);
  });
});
