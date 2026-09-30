import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT, main, runScan } from '../src/cli.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

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

const tmp = () => mkdtempSync(join(tmpdir(), 'noip-baseline-'));

describe('--baseline', () => {
  it('gates only on new findings: legacy debt passes, a new critical fails', async () => {
    const dir = tmp();
    const base = join(dir, 'base.json');
    writeFileSync(base, JSON.stringify(buildReport(loadDemoSnapshot(), 'demo')));
    // same cluster, nothing new: exit 0 despite existing critical findings
    expect(await runScan({ output: 'json', demo: true, failOn: 'critical', baseline: base })).toBe(EXIT.OK);
    expect(err).toMatch(/baseline: 0 new finding\(s\)/);
    // baseline without ci's debug shell: the critical finding (and chain) in ci is new today
    const s = loadDemoSnapshot();
    s.pods = s.pods.filter((p) => p.metadata?.name !== 'debug-shell');
    writeFileSync(base, JSON.stringify(buildReport(s, 'demo')));
    expect(await runScan({ output: 'json', demo: true, failOn: 'critical', baseline: base })).toBe(EXIT.FINDINGS_AT_THRESHOLD);
    expect(err).toMatch(/1 new risk chain\(s\)/);
    // without --fail-on the baseline only reports
    expect(await runScan({ output: 'json', demo: true, baseline: base })).toBe(EXIT.OK);
  });

  it('marks SARIF results new or unchanged, in scan and render', async () => {
    const dir = tmp();
    const s = loadDemoSnapshot();
    s.pods = s.pods.filter((p) => p.metadata?.name !== 'debug-shell');
    const base = join(dir, 'base.json');
    writeFileSync(base, JSON.stringify(buildReport(s, 'demo')));
    await runScan({ output: 'sarif', demo: true, baseline: base });
    const states = (JSON.parse(out).runs[0].results as Array<{ baselineState: string; partialFingerprints: Record<string, string> }>).map((r) => [r.partialFingerprints['noipFindingId/v1'], r.baselineState]);
    const fresh = states.filter(([, st]) => st === 'new').map(([id]) => id!);
    expect(fresh).toContain('NOIP-POD-001:Pod/ci/debug-shell/shell');
    for (const id of fresh) expect(id).toMatch(/debug-shell|Namespace\/ci/);
    expect(states.some(([, st]) => st === 'unchanged')).toBe(true);
    const cur = join(dir, 'cur.json');
    writeFileSync(cur, JSON.stringify(buildReport(loadDemoSnapshot(), 'demo')));
    out = '';
    await main(['node', 'noip', 'render', cur, '-o', 'sarif', '--baseline', base]);
    expect(JSON.parse(out).runs[0].results.every((r: { baselineState?: string }) => r.baselineState === 'new' || r.baselineState === 'unchanged')).toBe(true);
    expect(renderSarif(buildReport(loadDemoSnapshot(), 'demo')).runs[0]!.results!.every((r) => r.baselineState === undefined)).toBe(true);
  });

  it('refuses fleet scans and non-report baselines', async () => {
    const dir = tmp();
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, '{"x":1}');
    await expect(runScan({ output: 'json', demo: true, baseline: bad })).rejects.toThrow(/not a NOIP report/);
    const base = join(dir, 'b.json');
    writeFileSync(base, JSON.stringify(buildReport(loadDemoSnapshot(), 'demo')));
    await expect(runScan({ output: 'json', baseline: base, allContexts: true, outDir: dir })).rejects.toThrow(/--baseline applies to a single cluster/);
  });
});
