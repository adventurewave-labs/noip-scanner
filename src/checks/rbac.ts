import type { Check } from './types.js';

import type { RbacV1Subject, V1ClusterRoleBinding, V1RoleBinding } from '@kubernetes/client-node';

/** Subjects that mean "everyone" (or every workload) rather than a specific identity. */
const BROAD_GROUPS = new Set(['system:authenticated', 'system:unauthenticated', 'system:serviceaccounts']);
const isBroad = (s: RbacV1Subject) =>
  (s.kind === 'Group' && (BROAD_GROUPS.has(s.name) || s.name.startsWith('system:serviceaccounts:'))) || (s.kind === 'User' && s.name === 'system:anonymous');
const grantsClusterAdmin = (b: V1ClusterRoleBinding | V1RoleBinding) => b.roleRef.kind === 'ClusterRole' && b.roleRef.name === 'cluster-admin';

export const rbacChecks: Check[] = [
  {
    id: 'NOIP-RBAC-001',
    title: 'cluster-admin granted to a broad group or anonymous user',
    severity: 'critical',
    category: 'RBAC',
    controls: ['CIS-5.1.1'],
    remediation: 'Delete the binding; grant least-privilege roles to specific subjects.',
    // Covers ClusterRoleBindings (cluster-wide) and RoleBindings (namespace-wide admin). The built-in
    // `cluster-admin` binding to system:masters is expected and is not flagged.
    run: (snap, ctx) => [
      ...snap.clusterRoleBindings.filter(grantsClusterAdmin).flatMap((b) =>
        (b.subjects ?? []).filter(isBroad).map((s) => ({
          resource: { kind: 'ClusterRoleBinding', name: b.metadata?.name ?? 'unknown' },
          evidence: `roleRef=ClusterRole/cluster-admin subject=${s.kind}/${s.name}`,
        })),
      ),
      ...snap.roleBindings
        .filter((b) => grantsClusterAdmin(b) && !ctx.excludedNamespaces.has(b.metadata?.namespace ?? 'default'))
        .flatMap((b) =>
          (b.subjects ?? []).filter(isBroad).map((s) => ({
            resource: { kind: 'RoleBinding', namespace: b.metadata?.namespace ?? 'default', name: b.metadata?.name ?? 'unknown' },
            evidence: `roleRef=ClusterRole/cluster-admin subject=${s.kind}/${s.name} (admin of namespace ${b.metadata?.namespace ?? 'default'})`,
          })),
        ),
    ],
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
