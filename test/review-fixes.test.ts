// Regression tests for defects found in the independent review of the loop PRs.
import { describe, expect, it } from 'vitest';
import { loadManifests } from '../src/manifests.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport } from '../src/scan.js';
import { applySuppressions } from '../src/suppressions.js';
import { hardenedPod, ns, snap } from './helpers.js';

const covered = [{ metadata: { name: 'np', namespace: 'app' }, spec: { podSelector: {} } }];

describe('review fixes', () => {
  it('scans ephemeral containers (kubectl debug --profile=sysadmin)', () => {
    const pod = hardenedPod('app', 'p', (p) => {
      p.spec!.ephemeralContainers = [{ name: 'debugger', image: 'busybox', securityContext: { privileged: true, allowPrivilegeEscalation: true, readOnlyRootFilesystem: true, runAsNonRoot: true }, resources: {} }];
    });
    const ids = buildReport(snap({ namespaces: ns('app'), networkPolicies: covered, pods: [pod] }), 'live').findings.map((f) => [f.id, f.evidence]);
    expect(ids).toContainEqual(['NOIP-POD-001:Pod/app/p/debugger', 'spec.ephemeralContainers[debugger].securityContext.privileged=true']);
  });

  it('flags RoleBindings granting cluster-admin to broad subjects, and anonymous/serviceaccount groups', () => {
    const rb = (namespace: string, kind: string, name: string) => ({
      metadata: { name: 'rb', namespace },
      roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'cluster-admin' },
      subjects: [{ kind, name }],
    });
    const crb = { metadata: { name: 'anon' }, roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'User', name: 'system:anonymous' }, { kind: 'Group', name: 'system:serviceaccounts:ci' }] };
    const r = buildReport(snap({ roleBindings: [rb('app', 'Group', 'system:authenticated'), rb('kube-system', 'Group', 'system:authenticated'), rb('app2', 'User', 'alice')], clusterRoleBindings: [crb] }), 'live');
    expect(r.findings.map((f) => f.id)).toEqual(['NOIP-RBAC-001:ClusterRoleBinding/anon', 'NOIP-RBAC-001:RoleBinding/app/rb']);
    expect(r.findings[1]!.evidence).toBe('roleRef=ClusterRole/cluster-admin subject=Group/system:authenticated (admin of namespace app)');
  });

  it('attributes CronJob-created Jobs to the CronJob so IDs are stable across runs', () => {
    const run = (n: string) =>
      hardenedPod('app', `nightly-${n}-x`, (p) => {
        p.metadata!.ownerReferences = [{ apiVersion: 'batch/v1', kind: 'Job', name: `nightly-${n}`, uid: 'u', controller: true }];
        p.spec!.hostPID = true;
      });
    const ids = buildReport(snap({ namespaces: ns('app'), networkPolicies: covered, pods: [run('28765430'), run('28765490')] }), 'live').findings.map((f) => f.id);
    expect(ids).toEqual(['NOIP-POD-002:CronJob/app/nightly']);
    const plainJob = hardenedPod('app', 'migrate-abc', (p) => {
      p.metadata!.ownerReferences = [{ apiVersion: 'batch/v1', kind: 'Job', name: 'migrate', uid: 'u' }];
      p.spec!.hostPID = true;
    });
    expect(buildReport(snap({ namespaces: ns('app'), networkPolicies: covered, pods: [plainJob] }), 'live').findings[0]!.id).toBe('NOIP-POD-002:Job/app/migrate');
  });

  it('keeps every generateName object in manifest scans', async () => {
    const y = ['job-a-', 'job-b-'].map((g) => `apiVersion: v1\nkind: Pod\nmetadata: { generateName: ${g} }\nspec: { hostPID: true, containers: [] }\n`).join('---\n');
    const r = buildReport(await loadManifests(['-'], async () => y), 'manifests');
    expect(r.findings.map((f) => f.resource.name)).toEqual(['job-a-<generated:<stdin>:1>', 'job-b-<generated:<stdin>:6>']);
  });

  it('never emits "<stdin>" as a SARIF artifact URI but keeps the line', async () => {
    const r = buildReport(await loadManifests(['-'], async () => '\n\napiVersion: v1\nkind: Pod\nmetadata: { name: p }\nspec: { hostPID: true, containers: [] }\n'), 'manifests');
    const loc = renderSarif(r).runs[0]!.results![0]!.locations![0]!.physicalLocation!;
    expect(loc).toEqual({ artifactLocation: { uri: 'k8s/Pod/default/p' }, region: { startLine: 3 } });
  });

  it('does not call overlapping suppressions stale', () => {
    const f = buildReport(snap({ namespaces: ns('x') }), 'live').findings;
    const s = (extra: object) => ({ reason: 'isolated by service mesh', owner: 'o', expires: '2099-01-01', ...extra });
    const out = applySuppressions(f, [s({ check: 'NOIP-NET-001' }), s({ id: 'NOIP-NET-001:Namespace/x' })]);
    expect(out.suppressed).toHaveLength(1);
    expect(out.warnings).toEqual([]);
  });

  it('treats egress to 0.0.0.0/0 or ::/0 without exceptions as unrestricted', () => {
    const np = (cidr: string, except?: string[]) => ({ metadata: { name: `np-${except ? 'x' : 'o'}${cidr.length}`, namespace: 'app' }, spec: { podSelector: {}, egress: [{ to: [{ ipBlock: { cidr, except } }] }] } });
    const r = buildReport(snap({ namespaces: ns('app'), networkPolicies: [np('0.0.0.0/0'), np('::/0'), np('0.0.0.0/0', ['10.0.0.0/8']), np('10.0.0.0/8')] }), 'live');
    expect(r.findings.map((f) => f.evidence)).toEqual(['spec.egress[0] allows ipBlock ::/0 with no exceptions', 'spec.egress[0] allows ipBlock 0.0.0.0/0 with no exceptions']);
  });
});

describe('sparse inputs on the new paths', () => {
  it('RoleBinding cluster-admin grants with missing metadata/subjects', () => {
    const r = buildReport(
      snap({
        roleBindings: [
          { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'system:unauthenticated' }] },
          { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' } },
        ],
      }),
      'live',
    );
    expect(r.findings.map((f) => f.id)).toEqual(['NOIP-RBAC-001:RoleBinding/default/unknown']);
  });

  it('manifest RoleBindings, NetworkPolicies and ClusterRoleBindings without namespaces load', async () => {
    const y = [
      'apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: { name: rb }\nroleRef: { apiGroup: "", kind: ClusterRole, name: cluster-admin }\nsubjects: [{ kind: Group, name: system:authenticated }]',
      'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: { name: np }\nspec: { podSelector: {} }',
      'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: { name: crb }\nroleRef: { apiGroup: "", kind: ClusterRole, name: view }',
      'kind: Pod\nspec: { containers: [] }',
    ].join('\n---\n');
    const s = await loadManifests(['-'], async () => y);
    expect([s.roleBindings[0]!.metadata!.namespace, s.networkPolicies[0]!.metadata!.namespace, s.clusterRoleBindings.length, s.pods.length]).toEqual(['default', 'default', 1, 1]);
    expect(buildReport(s, 'manifests').findings.map((f) => f.id)).toContain('NOIP-RBAC-001:RoleBinding/default/rb');
  });

  it('reports a non-ENOENT read error message', async () => {
    await expect(loadManifests(['/proc/self/mem/x'])).rejects.toThrow(/cannot read \/proc\/self\/mem\/x/);
  });
});
