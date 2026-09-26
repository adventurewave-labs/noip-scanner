// Regression tests for the fifth independent review (r33–r36).
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { V1Pod } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { riskChains } from '../src/chains.js';
import { fixManifests } from '../src/fix.js';
import { loadManifests } from '../src/manifests.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, snap } from './helpers.js';

const crb = (name: string, subjects: object[]) => ({ metadata: { name }, roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects }) as never;
const rb = (ns: string, role: { kind: string; name: string }, subjects: object[]) => ({ metadata: { name: 'rb', namespace: ns }, roleRef: { apiGroup: '', ...role }, subjects }) as never;

describe('review 5', () => {
  it('honours the deprecated spec.serviceAccount field (#1)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-r5-'));
    writeFileSync(
      join(dir, 'm.yaml'),
      [
        'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: builder-admin}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\nsubjects: [{kind: ServiceAccount, name: builder, namespace: app}]',
        'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: legacy, namespace: app}\nspec:\n  template:\n    spec:\n      serviceAccount: builder\n      containers: [{name: c, image: x}]',
        'apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {name: ns-admin, namespace: app}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: r}\nsubjects: [{kind: ServiceAccount, name: default}]',
      ].join('\n---\n'),
    );
    const r = buildReport(await loadManifests([dir]), 'manifests');
    expect(r.riskChains!.map((c) => c.id)).toEqual(['CHAIN-SA-CLUSTER-ADMIN:app/builder:builder-admin']);
  });

  it('noip fix indexes each file once: thousands of objects in one file stay fast (#2)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-r5-'));
    const docs = Array.from({ length: 1500 }, (_, i) => `apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d${i}, namespace: n}\nspec:\n  template:\n    spec:\n      hostPID: true\n      containers: [{name: c, image: x}]`);
    writeFileSync(join(dir, 'big.yaml'), docs.join('\n---\n'));
    const t0 = performance.now();
    const res = await fixManifests(['big.yaml'], { cwd: dir, outDir: join(dir, 'out') });
    expect(res.applied.filter((a) => a.findingId.startsWith('NOIP-POD-002')).length).toBe(1500);
    expect(performance.now() - t0).toBeLessThan(8_000); // measured: ~20 s before indexing, ~0.8 s after
  }, 60_000);

  it('--min-severity applies to chains, and chains list only findings present in the report (#3)', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { minSeverity: 'critical' });
    expect(r.riskChains!.map((c) => c.severity)).toEqual(['critical']);
    const ids = new Set(r.findings.map((f) => f.id));
    for (const c of r.riskChains!) for (const id of c.findingIds) expect(ids.has(id)).toBe(true);
    // chain text doesn't change with the filter: built from every finding
    const full = buildReport(loadDemoSnapshot(), 'demo');
    expect(r.riskChains![0]!.steps).toEqual(full.riskChains![0]!.steps);
  });

  it('matches ServiceAccounts named in User form (#4)', () => {
    const s = snap({ pods: [hardenedPod('app', 'p')], clusterRoleBindings: [crb('user-form', [{ kind: 'User', name: 'system:serviceaccount:app:default' }])] });
    expect(riskChains(s, [], new Set()).map((c) => c.id)).toEqual(['CHAIN-SA-CLUSTER-ADMIN:app/default:user-form']);
  });

  it('cross-namespace default-SA grants, broad roles rated high, finished pods ignored (#7, #8, #9)', () => {
    const done = (p: V1Pod) => (p.status = { phase: 'Succeeded' });
    const s = snap({
      pods: [hardenedPod('b', 'p'), hardenedPod('c', 'job', done)],
      roleBindings: [rb('a', { kind: 'ClusterRole', name: 'edit' }, [{ kind: 'ServiceAccount', name: 'default', namespace: 'b' }]), rb('c', { kind: 'ClusterRole', name: 'admin' }, [{ kind: 'ServiceAccount', name: 'default' }])],
    });
    const chains = riskChains(s, [], new Set());
    expect(chains.map((c) => [c.id, c.severity])).toEqual([['CHAIN-DEFAULT-SA-ROLE:a:rb:b', 'high']]);
    expect(chains[0]!.title).toBe('Every workload in b without its own ServiceAccount inherits ClusterRole edit in namespace a');
  });
});
