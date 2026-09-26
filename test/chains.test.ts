import type { V1Pod } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { renderMetrics } from '../src/api/metrics.js';
import { riskChains } from '../src/chains.js';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, snap } from './helpers.js';

const crb = (name: string, subjects: object[]) => ({ metadata: { name }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'cluster-admin' }, subjects }) as never;
const replica = (ns: string, name: string, sa?: string, patch: (p: V1Pod) => void = () => {}) =>
  hardenedPod(ns, name, (p) => {
    p.metadata!.ownerReferences = [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-5d9f8c7b6', uid: 'u', controller: true }];
    if (sa) p.spec!.serviceAccountName = sa;
    patch(p);
  });

describe('risk chains', () => {
  it('finds the demo paths: a privileged pod with a cluster-admin token, and a default SA with a Role', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    expect(r.riskChains!.map((c) => [c.severity, c.id])).toEqual([
      ['critical', 'CHAIN-SA-CLUSTER-ADMIN:ci/default:ci-deployer-admin'],
      ['medium', 'CHAIN-DEFAULT-SA-ROLE:payments:payments-reader'],
    ]);
    const [admin] = r.riskChains!;
    expect(admin!.entryPoints).toEqual(['Pod/ci/debug-shell']);
    expect(admin!.findingIds).toEqual(expect.arrayContaining(['NOIP-RBAC-002:ClusterRoleBinding/ci-deployer-admin', 'NOIP-POD-001:Pod/ci/debug-shell/shell']));
    expect(admin!.steps[2]).toMatch(/host-level access \(NOIP-POD-001/);
  });

  it('covers service-account groups, collapses replicas, and honours automount=false and excluded namespaces', () => {
    const s = snap({
      pods: [
        replica('app', 'web-5d9f8c7b6-a', 'builder'),
        replica('app', 'web-5d9f8c7b6-b', 'builder'),
        hardenedPod('app', 'quiet', (p) => ((p.spec!.serviceAccountName = 'builder'), (p.spec!.automountServiceAccountToken = false))),
        hardenedPod('kube-system', 'sys'),
      ],
      clusterRoleBindings: [crb('all-sas', [{ kind: 'Group', name: 'system:serviceaccounts' }]), crb('ns-sas', [{ kind: 'Group', name: 'system:serviceaccounts:other' }])],
    });
    const chains = riskChains(s, [], new Set(['kube-system']));
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({ id: 'CHAIN-SA-CLUSTER-ADMIN:app/builder:all-sas', entryPoints: ['ReplicaSet/app/web-5d9f8c7b6'] });
    expect(chains[0]!.steps[2]).toMatch(/Code execution in any of them/);
  });

  it('matches a RoleBinding subject without a namespace to the binding namespace; ignores bindings to other SAs', () => {
    const rb = (ns: string, subjects: object[]) => ({ metadata: { name: 'rb', namespace: ns }, roleRef: { apiGroup: '', kind: 'Role', name: 'r' }, subjects }) as never;
    const s = snap({
      pods: [hardenedPod('a', 'p1'), hardenedPod('b', 'p2'), hardenedPod('ex', 'p3')],
      roleBindings: [rb('a', [{ kind: 'ServiceAccount', name: 'default' }]), rb('b', [{ kind: 'ServiceAccount', name: 'deployer', namespace: 'b' }]), rb('ex', [{ kind: 'ServiceAccount', name: 'default' }]), rb('c', [{ kind: 'ServiceAccount', name: 'default' }])],
    });
    expect(riskChains(s, [], new Set(['ex'])).map((c) => c.id)).toEqual(['CHAIN-DEFAULT-SA-ROLE:a:rb']);
  });

  it('renders escaped in markdown and HTML, and counts in metrics', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.riskChains![0]!.title = '<img src=x>|';
    r.riskChains![0]!.steps = ['[x](javascript:1)'];
    const md = renderMarkdown(r);
    expect(md).toContain('## Risk chains');
    expect(md).not.toMatch(/<img src=x>|\]\(javascript/);
    expect(renderMarkdown(r, 'es')).toContain('## Cadenas de riesgo');
    expect(renderHtml(r)).not.toContain('<img src=x>');
    expect(renderMetrics(r, { up: true, failures: 0 })).toContain('noip_risk_chains{severity="critical"} 1');
    expect(buildReport(snap(), 'live').riskChains).toBeUndefined();
  });
});

describe('edge cases (chains, metrics, OSCAL)', () => {
  it('handles many entry points, unnamed bindings, users and non-admin roles', () => {
    const pods = ['a', 'b', 'c', 'd'].map((n) => hardenedPod('app', n));
    const s = snap({
      pods,
      clusterRoleBindings: [
        { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'User', name: 'alice' }] } as never,
        { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'view' }, subjects: [{ kind: 'Group', name: 'system:authenticated' }] } as never,
        { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'system:authenticated' }] } as never,
      ],
      roleBindings: [{ metadata: { namespace: 'app' }, roleRef: { apiGroup: '', kind: 'Role', name: 'r' }, subjects: [{ kind: 'ServiceAccount', name: 'default' }] } as never, { roleRef: { apiGroup: '', kind: 'Role', name: 'r' } } as never],
    });
    const chains = riskChains(s, [], new Set());
    expect(chains.map((c) => c.id)).toEqual(['CHAIN-SA-CLUSTER-ADMIN:app/default:unknown', 'CHAIN-DEFAULT-SA-ROLE:app:unknown']);
    expect(chains[0]!.steps[0]).toMatch(/4 workload\(s\).*, …\)/);
    expect(chains[1]!.steps[1]).toMatch(/, …\)/);
  });

  it('metrics and OSCAL cope with manifest reports (no context, version facts or readiness)', async () => {
    const { renderOscal } = await import('../src/report/oscal.js');
    const r = buildReport(snap({ serverVersion: { gitVersion: 'n/a' }, context: undefined, pods: [], clusterRoleBindings: [{ metadata: { name: 'x' }, roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'system:unauthenticated' }] } as never] }), 'manifests');
    r.provenance.checksRun.push('NOIP-FUTURE-001');
    const text = renderMetrics(r, { up: true, failures: 0, durationSeconds: Number.NaN });
    expect(text).toContain('noip_scan_duration_seconds NaN');
    expect(text).toContain('context=""');
    expect(text).toContain('noip_check_failed{check="NOIP-FUTURE-001",severity="unknown"} 0');
    expect(text).not.toContain('noip_namespace_pod_security_level');
    const doc = JSON.stringify(renderOscal(r));
    expect(doc).toContain('Read-only Kubernetes posture scan of manifests');
    expect(doc).toContain('"kubernetes-kind"');
  });
});

describe('ServiceAccount-level token mounting', () => {
  const s = (sas: object[] | undefined, pod: (p: V1Pod) => void = () => {}) =>
    snap({ pods: [hardenedPod('app', 'p', pod)], clusterRoleBindings: [crb('x', [{ kind: 'ServiceAccount', name: 'default', namespace: 'app' }])], ...(sas ? { serviceAccounts: sas as never } : {}) });
  it('drops the chain when the ServiceAccount disables automount, unless the pod re-enables it', () => {
    const off = [{ metadata: { name: 'default', namespace: 'app' }, automountServiceAccountToken: false }];
    expect(riskChains(s(off), [], new Set())).toEqual([]);
    const podOn = riskChains(s(off, (p) => (p.spec!.automountServiceAccountToken = true)), [], new Set());
    expect(podOn).toHaveLength(1);
    expect(podOn[0]!.caveat).toMatch(/checked at pod and ServiceAccount level/);
  });
  it('states the caveat when the ServiceAccount object is not in the input', () => {
    expect(riskChains(s(undefined), [], new Set())[0]!.caveat).toMatch(/was not in the scanned input/);
    expect(riskChains(s([{ metadata: { name: 'other', namespace: 'app' } }]), [], new Set())[0]!.caveat).toMatch(/was not in the scanned input/);
  });
  it('reads ServiceAccounts from manifests', async () => {
    const { loadManifests } = await import('../src/manifests.js');
    const { mkdtempSync, writeFileSync } = await import('node:fs');
    const dir = mkdtempSync(`${(await import('node:os')).tmpdir()}/noip-sa-`);
    writeFileSync(`${dir}/sa.yaml`, 'apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: builder, namespace: app}\nautomountServiceAccountToken: false\nsecrets: [{name: tok}]\n');
    const snapshot = await loadManifests([dir]);
    expect(snapshot.serviceAccounts).toEqual([{ metadata: { name: 'builder', namespace: 'app' }, automountServiceAccountToken: false }]);
  });
});
