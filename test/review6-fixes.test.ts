// Regression tests for the sixth independent review (r42–r43).
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT, runScan } from '../src/cli.js';
import { riskChains } from '../src/chains.js';
import { diffReports } from '../src/report/diff.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, snap } from './helpers.js';

let out = '';
beforeEach(() => {
  out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((s) => ((out += String(s)), true));
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => vi.restoreAllMocks());

describe('review 6', () => {
  it('a finding suppressed in the baseline and active now is new for the gate and in SARIF alike (#1)', async () => {
    const id = 'NOIP-POD-004:DaemonSet/monitoring/node-exporter';
    const dir = mkdtempSync(join(tmpdir(), 'noip-r6-'));
    const base = join(dir, 'b.json');
    writeFileSync(base, JSON.stringify(buildReport(loadDemoSnapshot(), 'demo', { suppressions: [{ id, reason: 'r', owner: 'o', expires: '2099-01-01' }] })));
    expect(await runScan({ output: 'sarif', demo: true, failOn: 'high', baseline: base })).toBe(EXIT.FINDINGS_AT_THRESHOLD);
    const res = JSON.parse(out).runs[0].results.find((r: { partialFingerprints: Record<string, string> }) => r.partialFingerprints['noipFindingId/v1'] === id);
    expect(res.baselineState).toBe('new');
  });

  it('warns when the severity filter differs between baseline and scan (#4)', () => {
    const d = diffReports(buildReport(loadDemoSnapshot(), 'demo', { minSeverity: 'critical' }), buildReport(loadDemoSnapshot(), 'demo'));
    expect(d.warnings).toContain('severity filter differs (critical vs none): findings below the earlier filter show as new');
  });

  it('exposure names every Service that exposes a chain entry point, and says internal LBs are not distinguished (#6, #8)', () => {
    const pod = hardenedPod('app', 'web', (p) => (p.metadata!.labels = { app: 'web' }));
    const svc = (name: string) => ({ metadata: { name, namespace: 'app' }, spec: { type: 'LoadBalancer', selector: { app: 'web' } } }) as never;
    const crb = { metadata: { name: 'x' }, roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'ServiceAccount', name: 'default', namespace: 'app' }] } as never;
    const chains = riskChains(snap({ pods: [pod], services: [svc('b'), svc('a')], clusterRoleBindings: [crb] }), [], new Set());
    expect(chains[0]!.steps.at(-1)).toMatch(/\(Services app\/a, app\/b\)/);
    const priv = hardenedPod('app', 'p', (p) => ((p.metadata!.labels = { app: 'web' }), (p.spec!.hostPID = true)));
    const r = buildReport(snap({ pods: [priv], services: [svc('a')] }), 'live');
    expect(r.riskChains![0]!.caveat).toMatch(/internal-only load balancer is still listed/);
  });
});
