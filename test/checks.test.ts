import type { RbacV1Subject } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { ALL_CHECKS, SYSTEM_NAMESPACES } from '../src/checks/index.js';
import { workloadOf } from '../src/checks/workload.js';
import { buildReport } from '../src/scan.js';
import type { ClusterSnapshot } from '../src/types.js';
import { hardenedPod, ns, snap } from './helpers.js';

const ids = (s: ClusterSnapshot, opts = {}) => buildReport(s, 'live', opts).findings.map((f) => f.id);
const covered = () => [{ metadata: { name: 'np', namespace: 'app' }, spec: { podSelector: {} } }];

describe('check registry', () => {
  it('has unique ids and stays within the ~15-control cap (ADR-0004)', () => {
    const idList = ALL_CHECKS.map((c) => c.id);
    expect(new Set(idList).size).toBe(idList.length);
    expect(idList.length).toBeLessThanOrEqual(15);
  });

  it('a hardened pod in a covered namespace produces no findings', () => {
    expect(ids(snap({ namespaces: ns('app'), networkPolicies: covered(), pods: [hardenedPod()] }))).toEqual([]);
  });
});

describe('pod checks', () => {
  const one = (patch: Parameters<typeof hardenedPod>[2]) =>
    ids(snap({ namespaces: ns('app'), networkPolicies: covered(), pods: [hardenedPod('app', 'p', patch)] }));

  it('NOIP-POD-001 privileged', () => {
    expect(one((p) => (p.spec!.containers[0]!.securityContext!.privileged = true))).toEqual(['NOIP-POD-001:Pod/app/p/c']);
  });
  it('NOIP-POD-002/003/004 host namespaces', () => {
    expect(one((p) => (p.spec!.hostPID = true))).toEqual(['NOIP-POD-002:Pod/app/p']);
    expect(one((p) => (p.spec!.hostIPC = true))).toEqual(['NOIP-POD-003:Pod/app/p']);
    expect(one((p) => (p.spec!.hostNetwork = true))).toEqual(['NOIP-POD-004:Pod/app/p']);
  });
  it('NOIP-POD-005 privilege escalation unset or true', () => {
    expect(one((p) => delete p.spec!.containers[0]!.securityContext!.allowPrivilegeEscalation)).toEqual(['NOIP-POD-005:Pod/app/p/c']);
    const f = buildReport(
      snap({ namespaces: ns('app'), networkPolicies: covered(), pods: [hardenedPod('app', 'p', (p) => (p.spec!.containers[0]!.securityContext!.allowPrivilegeEscalation = true))] }),
      'live',
    ).findings[0]!;
    expect(f.evidence).toBe('spec.containers[c].securityContext.allowPrivilegeEscalation=true');
  });
  it('NOIP-POD-006 honours pod-level securityContext and flags explicit root', () => {
    expect(one((p) => delete p.spec!.securityContext)).toEqual(['NOIP-POD-006:Pod/app/p/c']);
    expect(one((p) => (p.spec!.securityContext = { runAsUser: 1000 }))).toEqual([]);
    expect(one((p) => (p.spec!.containers[0]!.securityContext!.runAsUser = 0))).toEqual(['NOIP-POD-006:Pod/app/p/c']);
    expect(one((p) => (p.spec!.securityContext = { runAsNonRoot: false }))).toEqual(['NOIP-POD-006:Pod/app/p/c']);
  });
  it('NOIP-POD-007 writable root fs, NOIP-POD-008 limits', () => {
    expect(one((p) => (p.spec!.containers[0]!.securityContext!.readOnlyRootFilesystem = false))).toEqual(['NOIP-POD-007:Pod/app/p/c']);
    const r = buildReport(snap({ namespaces: ns('app'), networkPolicies: covered(), pods: [hardenedPod('app', 'p', (p) => delete p.spec!.containers[0]!.resources!.limits!.memory)] }), 'live');
    expect(r.findings.map((f) => f.evidence)).toEqual(['spec.containers[c].resources.limits missing memory']);
  });
  it('NOIP-POD-009 secret env var and envFrom, including init containers, with names only', () => {
    const r = buildReport(
      snap({
        namespaces: ns('app'),
        networkPolicies: covered(),
        pods: [
          hardenedPod('app', 'p', (p) => {
            p.spec!.containers[0]!.env = [{ name: 'PW', valueFrom: { secretKeyRef: { name: 's', key: 'k' } } }, { name: 'PLAIN', value: 'x' }];
            p.spec!.initContainers = [{ ...p.spec!.containers[0]!, name: 'init', env: undefined, envFrom: [{ secretRef: { name: 'all' } }] }];
          }),
        ],
      }),
      'live',
    );
    expect(r.findings.map((f) => [f.id, f.evidence])).toEqual([
      ['NOIP-POD-009:Pod/app/p/c', 'spec.containers[c]: env[PW] <- secret s/k'],
      ['NOIP-POD-009:Pod/app/p/init', 'spec.initContainers[init]: envFrom <- secret all'],
    ]);
  });
  it('skips system namespaces unless asked', () => {
    const s = snap({ namespaces: ns('kube-system'), pods: [hardenedPod('kube-system', 'kp', (p) => (p.spec!.hostNetwork = true))] });
    expect(ids(s)).toEqual([]);
    expect(ids(s, { includeSystemNamespaces: true })).toEqual(['NOIP-NET-001:Namespace/kube-system', 'NOIP-POD-004:Pod/kube-system/kp']);
    expect(SYSTEM_NAMESPACES).toContain('kube-system');
  });
  it('honours extra excluded namespaces', () => {
    expect(ids(snap({ namespaces: ns('skipme') }), { excludeNamespaces: ['skipme'] })).toEqual([]);
  });
});

describe('workload attribution', () => {
  it('collapses Deployment replicas into one finding', () => {
    const replica = (n: string) =>
      hardenedPod('app', `web-5d9f-${n}`, (p) => {
        p.metadata!.labels = { 'pod-template-hash': '5d9f' };
        p.metadata!.ownerReferences = [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-5d9f', uid: 'u', controller: true }];
        p.spec!.hostPID = true;
      });
    expect(ids(snap({ namespaces: ns('app'), networkPolicies: covered(), pods: [replica('a'), replica('b')] }))).toEqual(['NOIP-POD-002:Deployment/app/web']);
  });
  it('resolves other owners and falls back safely', () => {
    const owned = (kind: string, name: string, labels?: Record<string, string>) =>
      workloadOf({ metadata: { name: 'x', namespace: 'n', labels, ownerReferences: [{ apiVersion: 'v1', kind, name, uid: 'u' }] } });
    expect(owned('DaemonSet', 'ds')).toEqual({ kind: 'DaemonSet', namespace: 'n', name: 'ds' });
    expect(owned('ReplicaSet', 'bare-rs')).toEqual({ kind: 'ReplicaSet', namespace: 'n', name: 'bare-rs' });
    expect(owned('Node', 'node-1')).toEqual({ kind: 'Pod', namespace: 'n', name: 'x' });
    expect(workloadOf({})).toEqual({ kind: 'Pod', namespace: 'default', name: 'unknown' });
  });
});

describe('network checks', () => {
  it('NOIP-NET-001 flags uncovered namespaces only', () => {
    expect(ids(snap({ namespaces: ns('app', 'bare'), networkPolicies: covered() }))).toEqual(['NOIP-NET-001:Namespace/bare']);
  });
  it('NOIP-NET-002 flags egress rules without a destination', () => {
    const r = buildReport(
      snap({
        namespaces: ns('app'),
        networkPolicies: [
          { metadata: { name: 'open', namespace: 'app' }, spec: { podSelector: {}, egress: [{ to: [{ podSelector: {} }] }, { ports: [{ port: 443 }] }] } },
          { metadata: { name: 'scoped', namespace: 'app' }, spec: { podSelector: {}, egress: [{ to: [{ ipBlock: { cidr: '10.0.0.0/8' } }] }] } },
        ],
      }),
      'live',
    );
    expect(r.findings.map((f) => [f.id, f.evidence])).toEqual([["NOIP-NET-002:NetworkPolicy/app/open", "spec.egress[1] has no 'to' selector (all destinations allowed)"]]);
  });
});

describe('rbac checks', () => {
  const crb = (name: string, subjects: RbacV1Subject[], role = 'cluster-admin') => ({
    metadata: { name },
    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: role },
    subjects,
  });
  it('does not flag the built-in system:masters binding', () => {
    expect(ids(snap({ clusterRoleBindings: [crb('cluster-admin', [{ kind: 'Group', name: 'system:masters' }])] }))).toEqual([]);
  });
  it('NOIP-RBAC-001 broad groups, NOIP-RBAC-002 default SA, ignores other roles', () => {
    expect(
      ids(
        snap({
          clusterRoleBindings: [
            crb('oops', [{ kind: 'Group', name: 'system:authenticated' }]),
            crb('ci', [{ kind: 'ServiceAccount', name: 'default', namespace: 'ci' }]),
            crb('view', [{ kind: 'ServiceAccount', name: 'default', namespace: 'ci' }], 'view'),
          ],
        }),
      ),
    ).toEqual(['NOIP-RBAC-001:ClusterRoleBinding/oops', 'NOIP-RBAC-002:ClusterRoleBinding/ci']);
  });
  it('NOIP-RBAC-003 default SA in a RoleBinding outside system namespaces', () => {
    const rb = (namespace: string) => ({
      metadata: { name: 'rb', namespace },
      roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'r' },
      subjects: [{ kind: 'ServiceAccount', name: 'default' }],
    });
    const r = buildReport(snap({ roleBindings: [rb('app'), rb('kube-system')] }), 'live');
    expect(r.findings.map((f) => [f.id, f.evidence])).toEqual([['NOIP-RBAC-003:RoleBinding/app/rb', 'roleRef=Role/r subject=ServiceAccount/app/default']]);
  });
});

describe('defensive fallbacks for sparse objects', () => {
  it('handles bindings and policies with missing metadata and subjects', () => {
    const r = buildReport(
      snap({
        clusterRoleBindings: [
          { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'system:unauthenticated' }, { kind: 'ServiceAccount', name: 'default' }] },
          { roleRef: { apiGroup: '', kind: 'ClusterRole', name: 'cluster-admin' } },
        ],
        roleBindings: [{ roleRef: { apiGroup: '', kind: 'Role', name: 'r' }, subjects: [{ kind: 'ServiceAccount', name: 'default' }] }, { roleRef: { apiGroup: '', kind: 'Role', name: 'r' } }],
        networkPolicies: [{ spec: { podSelector: {}, egress: [{}] } }],
        namespaces: [{ metadata: {} }],
      }),
      'live',
    );
    expect(r.findings.map((f) => f.id).sort()).toEqual([
      'NOIP-NET-002:NetworkPolicy/default/unknown',
      'NOIP-RBAC-001:ClusterRoleBinding/unknown',
      'NOIP-RBAC-002:ClusterRoleBinding/unknown',
      'NOIP-RBAC-003:RoleBinding/default/unknown',
    ]);
    expect(r.findings.find((f) => f.checkId === 'NOIP-RBAC-002')!.evidence).toContain('ServiceAccount/?/default');
  });
});

describe('NOIP-NS-001 Pod Security Admission', () => {
  const nsWith = (name: string, level?: string) => ({ metadata: { name, labels: level ? { 'pod-security.kubernetes.io/enforce': level } : undefined } });
  const np = (n: string) => ({ metadata: { name: 'np', namespace: n }, spec: { podSelector: {} } });
  it('passes baseline/restricted, flags unset or privileged, skips system namespaces', () => {
    const r = buildReport(
      snap({
        namespaces: [nsWith('a', 'restricted'), nsWith('b', 'baseline'), nsWith('c', 'privileged'), nsWith('d'), nsWith('kube-system')],
        networkPolicies: ['a', 'b', 'c', 'd'].map(np),
      }),
      'live',
    );
    expect(r.findings.map((f) => [f.id, f.evidence])).toEqual([
      ['NOIP-NS-001:Namespace/c', 'metadata.labels["pod-security.kubernetes.io/enforce"]=privileged'],
      ['NOIP-NS-001:Namespace/d', 'metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)'],
    ]);
  });
});
