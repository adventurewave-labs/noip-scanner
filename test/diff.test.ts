import { describe, expect, it } from 'vitest';
import { diffReports, regressed, renderDiffMarkdown } from '../src/report/diff.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import type { ClusterSnapshot } from '../src/types.js';

const T0 = new Date('2026-08-26T00:00:00Z');
const T1 = new Date('2026-09-26T00:00:00Z');
const before = () => buildReport(loadDemoSnapshot(), 'demo', { now: T0 });

/** Next month: debug pod removed (resolved), a new hostPID pod appears, frontend now mounts a different secret. */
function afterSnapshot(): ClusterSnapshot {
  const s = loadDemoSnapshot();
  s.pods = s.pods.filter((p) => p.metadata?.name !== 'debug-shell');
  s.pods.push({ metadata: { name: 'tracer', namespace: 'shop' }, spec: { hostPID: true, securityContext: { runAsNonRoot: true }, containers: [] } });
  const api = s.pods.find((p) => p.metadata?.name?.startsWith('api-'))!;
  api.spec!.containers[0]!.env = [{ name: 'STRIPE_KEY', valueFrom: { secretKeyRef: { name: 'stripe-v2', key: 'api-key' } } }];
  return s;
}

describe('noip diff', () => {
  it('classifies new, resolved, changed and unchanged findings and control flips', () => {
    const d = diffReports(before(), buildReport(afterSnapshot(), 'demo', { now: T1 }));
    expect(d.new.map((f) => f.id)).toEqual(['NOIP-POD-002:Pod/shop/tracer']);
    expect(d.resolved.map((f) => f.id)).toContain('NOIP-POD-001:Pod/ci/debug-shell/shell');
    expect(d.changed).toEqual([{ id: 'NOIP-POD-009:Deployment/payments/api/api', before: 'spec.containers[api]: env[STRIPE_KEY] <- secret stripe/api-key', after: 'spec.containers[api]: env[STRIPE_KEY] <- secret stripe-v2/api-key' }]);
    expect(d.controls).toEqual(expect.arrayContaining([{ id: 'CIS-5.2.1', from: 'fail', to: 'pass' }, { id: 'CIS-5.2.3', from: 'fail', to: 'pass' }]));
    expect(d.unchanged).toBeGreaterThan(10);
    expect(d.scoreDelta).toBeGreaterThan(0);
    expect(d.warnings).toEqual([]);
    expect(regressed(d, 'critical')).toBe(true);
  });

  it('does not count newly suppressed findings as resolved', () => {
    const id = 'NOIP-POD-004:DaemonSet/monitoring/node-exporter';
    const after = buildReport(loadDemoSnapshot(), 'demo', { now: T1, suppressions: [{ id, reason: 'host network required for metrics', owner: 'sre', expires: '2099-01-01' }] });
    const d = diffReports(before(), after);
    expect(d.resolved).toEqual([]);
    expect(d.newlySuppressed).toEqual([id]);
    expect(regressed(d, 'low')).toBe(false);
    expect(renderDiffMarkdown(d)).toContain(`## Newly suppressed (accepted risk)\n\n- \`${id}\``);
  });

  it('warns when comparing different sources, targets or scopes, and notes check-set changes', () => {
    const a = before();
    const b = buildReport(loadDemoSnapshot(), 'live', { now: T1, includeSystemNamespaces: true });
    b.provenance.cluster.context = undefined;
    b.provenance.checksRun = [...b.provenance.checksRun.slice(1), 'NOIP-POD-010'];
    const d = diffReports(a, b);
    expect(d.warnings).toEqual(['comparing a demo report with a live report', 'different targets: demo-shop vs n/a', 'excluded namespaces differ between the two scans']);
    expect(d.checksAdded).toEqual(['NOIP-POD-010']);
    expect(d.checksRemoved).toEqual(['NOIP-POD-001']);
    const md = renderDiffMarkdown(d);
    expect(md).toContain('## Check set changed');
    expect(md).toContain('⚠️ comparing a demo report');
  });

  it('renders markdown with every section', () => {
    const md = renderDiffMarkdown(diffReports(before(), buildReport(afterSnapshot(), 'demo', { now: T1 })));
    for (const h of ['# NOIP posture drift', '## New findings', '## Resolved', '## Changed evidence', '## Control status changes']) expect(md).toContain(h);
    expect(renderDiffMarkdown(diffReports(before(), before()))).toContain('None.');
  });
});

describe('noip diff with suppressions on both sides', () => {
  it('only lists suppressions that are new in the later report', () => {
    const s = (id: string) => ({ id, reason: 'accepted for this quarter', owner: 'sre', expires: '2099-01-01' });
    const a = buildReport(loadDemoSnapshot(), 'demo', { now: T0, suppressions: [s('NOIP-POD-004:DaemonSet/monitoring/node-exporter')] });
    const b = buildReport(loadDemoSnapshot(), 'demo', {
      now: T1,
      suppressions: [s('NOIP-POD-004:DaemonSet/monitoring/node-exporter'), s('NOIP-POD-003:Pod/ci/debug-shell')],
    });
    const d = diffReports(a, b);
    expect(d.newlySuppressed).toEqual(['NOIP-POD-003:Pod/ci/debug-shell']);
    expect(d.resolved).toEqual([]);
    b.provenance.checksRun = [...b.provenance.checksRun, 'NOIP-POD-010'];
    expect(renderDiffMarkdown(diffReports(a, b))).toContain('Added: NOIP-POD-010 · Removed: —');
  });
});

describe('noip diff: chains, Pod Security readiness, images', () => {
  it('reports new/resolved chains, readiness changes and image changes; a new chain counts as a regression', () => {
    const a = before();
    const s = loadDemoSnapshot();
    // payments drops its default-SA RoleBinding (chain resolved); ci's debug shell is removed (critical chain resolved,
    // ci readiness changes); a new image appears.
    s.roleBindings = [];
    s.pods = s.pods.filter((p) => p.metadata?.name !== 'debug-shell');
    s.pods.push({ metadata: { name: 'new', namespace: 'shop' }, spec: { securityContext: { runAsNonRoot: true, seccompProfile: { type: 'RuntimeDefault' } }, containers: [{ name: 'c', image: 'ghcr.io/acme/new:1', securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ['ALL'] } } }] } });
    const b = buildReport(s, 'demo', { now: T1 });
    const d = diffReports(a, b);
    expect(d.chains.resolved.map((c) => c.severity).sort()).toEqual(['critical', 'medium']);
    expect(d.chains.new).toEqual([]);
    expect(d.images.added).toEqual(['ghcr.io/acme/new:1']);
    expect(d.podSecurity).toEqual(expect.arrayContaining([{ namespace: 'ci', from: 'privileged', to: 'restricted' }]));
    const back = diffReports(b, a);
    expect(back.chains.new.map((c) => c.severity)).toContain('critical');
    expect(regressed({ ...back, new: [] }, 'critical')).toBe(true); // the chain alone trips the gate
    const md = renderDiffMarkdown(d);
    expect(md).toContain('## Risk chains');
    expect(md).toContain('## Pod Security readiness changes');
    expect(md).toContain('## Images');
  });

  it('escapes every value from untrusted report files', () => {
    const a = before();
    const b = before();
    b.findings[0] = { ...b.findings[0]!, id: 'X`<img src=x>`', evidence: '<script>alert(1)</script> | [x](javascript:1)' };
    b.provenance.cluster.context = '<b>ctx</b>';
    const md = renderDiffMarkdown(diffReports(a, b));
    expect(md).not.toMatch(/<script>|<b>ctx|\]\(javascript/);
  });
});
