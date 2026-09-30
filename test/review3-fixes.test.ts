// Regression tests for the third independent review (loop 3). One test per confirmed defect.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import { EXIT, main, runScan } from '../src/cli.js';
import { buildHistory, renderHistoryHtml, renderHistoryMarkdown } from '../src/report/history.js';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { executiveSummary } from '../src/report/priorities.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const demo = (at = '2026-09-01T00:00:00Z') => buildReport(loadDemoSnapshot(), 'demo', { now: new Date(at) });

describe('review 3: noip history treats report files as untrusted', () => {
  it('coerces numeric fields, so HTML/markdown cannot be injected through them (#1)', () => {
    const r = demo() as unknown as { summary: Record<string, unknown> & { bySeverity: Record<string, unknown> } };
    r.summary.findings = '<img src=x onerror=alert(1)>';
    r.summary.controlsFailed = '<script>1</script>';
    r.summary.bySeverity.critical = '<svg onload=alert(2)>';
    const h = buildHistory([{ file: 'evil.json', report: r }]);
    expect(h.targets[0]!.points[0]).toMatchObject({ findings: 0, controlsFailed: 0, bySeverity: { critical: 0 } });
    for (const out of [renderHistoryHtml(h), renderHistoryMarkdown(h)]) expect(out).not.toMatch(/<img|<script>1|<svg onload/);
  });

  it('accepts only strict UTC ISO timestamps (#2)', () => {
    const r = demo();
    r.provenance.scannedAt = 'Sep 1 2026 (<img src=x onerror=alert(1)> | injected)';
    const h = buildHistory([{ file: 'x.json', report: r }]);
    expect(h.targets).toEqual([]);
    expect(h.skipped).toEqual([{ file: 'x.json', reason: 'invalid scannedAt' }]);
  });

  it('does not crash on a non-string gitSha or version (#3)', () => {
    const r = demo() as unknown as { provenance: { scanner: Record<string, unknown> } };
    r.provenance.scanner.gitSha = 12345;
    r.provenance.scanner.version = { x: 1 };
    const h = buildHistory([{ file: 'x.json', report: r }]);
    expect(h.targets[0]!.points[0]).toMatchObject({ gitSha: 'unknown', scannerVersion: 'unknown' });
    expect(renderHistoryMarkdown(h)).toContain('unknown (unknown)');
  });

  it('flags a namespace-scope change as not comparable (#4)', () => {
    const b = buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-09-02T00:00:00Z'), includeSystemNamespaces: true });
    const h = buildHistory([
      { file: 'a', report: demo() },
      { file: 'b', report: b },
    ]);
    expect(h.targets[0]!.points[1]).toMatchObject({ delta: null, scopeChanged: ['namespaces'] });
    expect(renderHistoryMarkdown(h)).toContain('not comparable: namespace scope changed');
    expect(renderHistoryMarkdown(h, 'es')).toContain('no comparable: cambió el alcance de namespaces');
  });
});

describe('review 3: distribution', () => {
  it('the action keeps every path of a multi-line manifests input (#5)', () => {
    const action = parse(readFileSync('action.yml', 'utf8')) as { runs: { steps: Array<{ run?: string }> } };
    const run = action.runs.steps.find((s) => s.run?.includes('IN_MANIFESTS'))!.run!;
    expect(run).toContain(`read -ra paths -d '' <<< "$IN_MANIFESTS" || true`);
    // One scan; SARIF and the summary are rendered from the same report (#14).
    expect(run.match(/"\$NOIP_BIN" scan /g)).toHaveLength(1);
    expect(run).toContain('"$NOIP_BIN" render "$IN_REPORT" -o sarif');
  });

  it('the pre-commit hook skips Helm chart templates (#6)', () => {
    const [hook] = parse(readFileSync('.pre-commit-hooks.yaml', 'utf8')) as Array<{ exclude: string }>;
    const re = new RegExp(hook!.exclude);
    expect(re.test('charts/app/templates/deployment.yaml')).toBe(true);
    expect(re.test('templates/x.yml')).toBe(true);
    expect(re.test('k8s/deployment.yaml')).toBe(false);
  });
});

describe('review 3: report wording', () => {
  it('Spanish priorities name the scope instead of implying a count; NET-002 is namespace-scoped (#7)', () => {
    const r = demo();
    const md = renderMarkdown(r, 'es');
    expect(md).not.toMatch(/afecta un namespace|afecta una carga de trabajo/);
    expect(md).toMatch(/alcance: namespace, \d+ recurso\(s\)/);
    r.findings = r.findings.filter((f) => f.checkId === 'NOIP-NET-002');
    const p = executiveSummary(r).priorities;
    for (const x of p) expect(x.scope).toBe('namespace');
  });

  it('network metadata is translated and escaped (#8)', () => {
    const r = demo();
    r.network = { source: 'k8s-netinspect', cni: 'calico<b>|x', toolVersion: '1.0', inputSha256: 'ab`c', checks: [{ name: 'dns', status: 'pass' }] } as never;
    const es = renderMarkdown(r, 'es');
    expect(es).toContain('versión de la herramienta: 1.0');
    expect(es).toContain('CNI: calico&lt;b&gt;\\|x');
    expect(es).toContain('`` ab`c ``');
    const html = renderHtml(r, 'es');
    expect(html).toContain('CNI: calico&lt;b&gt;|x · versión de la herramienta: 1.0');
  });
});

describe('review 3: CLI', () => {
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

  it('refuses manifests together with --contexts/--all-contexts (#9)', async () => {
    await expect(runScan({ output: 'json', manifests: ['test/fixtures/misconfig'], allContexts: true })).rejects.toThrow(/--all-contexts/);
    await main(['node', 'noip', 'scan', 'test/fixtures/misconfig', '--contexts', 'a', '--out-dir', '/tmp/x']);
    expect(process.exitCode).toBe(EXIT.ERROR);
  });

  it('noip render turns one saved report into md, html and sarif (#14)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-render-'));
    const f = join(dir, 'r.json');
    writeFileSync(f, JSON.stringify(demo()));
    await main(['node', 'noip', 'render', f]);
    expect(out).toMatch(/^# NOIP posture report/);
    out = '';
    await main(['node', 'noip', 'render', f, '-o', 'sarif']);
    expect(JSON.parse(out).version).toBe('2.1.0');
    await main(['node', 'noip', 'render', f, '-o', 'html', '--lang', 'es', '--out', join(dir, 'r.html')]);
    expect(readFileSync(join(dir, 'r.html'), 'utf8')).toContain('<html lang="es"');
    writeFileSync(f, '{"nope":1}');
    await main(['node', 'noip', 'render', f]);
    expect(process.exitCode).toBe(EXIT.ERROR);
    expect(err).toMatch(/not a NOIP report/);
  });
});
