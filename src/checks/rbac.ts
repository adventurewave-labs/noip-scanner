import type { Check } from './types.js';

const BROAD_GROUPS = new Set(['system:authenticated', 'system:unauthenticated']);

export const rbacChecks: Check[] = [
  {
    id: 'NOIP-RBAC-001',
    title: 'cluster-admin granted to a broad group',
    severity: 'critical',
    category: 'RBAC',
    controls: ['CIS-5.1.1'],
    remediation: 'Delete the binding; grant least-privilege roles to specific subjects.',
    // Note: the built-in `cluster-admin` binding to system:masters is expected and is not flagged.
    run: (snap) =>
      snap.clusterRoleBindings
        .filter((b) => b.roleRef.kind === 'ClusterRole' && b.roleRef.name === 'cluster-admin')
        .flatMap((b) =>
          (b.subjects ?? [])
            .filter((s) => s.kind === 'Group' && BROAD_GROUPS.has(s.name))
            .map((s) => ({
              resource: { kind: 'ClusterRoleBinding', name: b.metadata?.name ?? 'unknown' },
              evidence: `roleRef=ClusterRole/cluster-admin subject=Group/${s.name}`,
            })),
        ),
  },
  {
    id: 'NOIP-RBAC-002',
    title: 'cluster-admin granted to a default ServiceAccount',
    severity: 'high',
    category: 'RBAC',
    controls: ['CIS-5.1.1', 'CIS-5.1.5'],
    remediation: 'Create a dedicated ServiceAccount with a least-privilege role; never bind cluster-admin to `default`.',
    run: (snap) =>
      snap.clusterRoleBindings
        .filter((b) => b.roleRef.kind === 'ClusterRole' && b.roleRef.name === 'cluster-admin')
        .flatMap((b) =>
          (b.subjects ?? [])
            .filter((s) => s.kind === 'ServiceAccount' && s.name === 'default')
            .map((s) => ({
              resource: { kind: 'ClusterRoleBinding', name: b.metadata?.name ?? 'unknown' },
              evidence: `roleRef=ClusterRole/cluster-admin subject=ServiceAccount/${s.namespace ?? '?'}/default`,
            })),
        ),
  },
  {
    id: 'NOIP-RBAC-003',
    title: 'Role bound to a default ServiceAccount',
    severity: 'medium',
    category: 'RBAC',
    controls: ['CIS-5.1.5'],
    remediation: 'Bind the role to a named ServiceAccount and leave `default` without permissions.',
    run: (snap, ctx) =>
      snap.roleBindings
        .filter((b) => !ctx.excludedNamespaces.has(b.metadata?.namespace ?? 'default'))
        .flatMap((b) =>
          (b.subjects ?? [])
            .filter((s) => s.kind === 'ServiceAccount' && s.name === 'default')
            .map((s) => ({
              resource: { kind: 'RoleBinding', namespace: b.metadata?.namespace ?? 'default', name: b.metadata?.name ?? 'unknown' },
              evidence: `roleRef=${b.roleRef.kind}/${b.roleRef.name} subject=ServiceAccount/${s.namespace ?? b.metadata?.namespace ?? '?'}/default`,
            })),
        ),
  },
];
