import type { RbacV1Subject as V1Subject, V1Pod } from '@kubernetes/client-node';
import { workloadOf } from './checks/workload.js';
import { resourceKey } from './scan.js';
import type { ClusterSnapshot, Finding, Severity } from './types.js';

/**
 * Risk chains: findings that compound. A single finding says "this is weak"; a chain says "these together
 * give an attacker X". Deterministic and derived only from the snapshot NOIP already reads; not scored.
 *
 * Token mounting follows Kubernetes: the pod's automountServiceAccountToken, else the ServiceAccount's, else true.
 * When the ServiceAccount object isn't in the input (e.g. a manifest scan without it), the chain says so.
 */
export interface RiskChain {
  id: string;
  severity: Severity;
  title: string;
  /** Plain-language path, one step per line. */
  steps: string[];
  /** Workloads that start the chain. */
  entryPoints: string[];
  /** NOIP findings that make up the chain (IDs). */
  findingIds: string[];
  caveat: string;
}

const CAVEAT_UNKNOWN_SA = 'The ServiceAccount object was not in the scanned input, so an SA-level automountServiceAccountToken: false could not be checked.';
const CAVEAT_NONE = 'Token mounting was checked at pod and ServiceAccount level (the pod setting wins, as in Kubernetes).';
const HOST_ACCESS = new Set(['NOIP-POD-001', 'NOIP-POD-002', 'NOIP-POD-004']);

const saOf = (p: V1Pod) => `${p.metadata?.namespace ?? 'default'}/${p.spec?.serviceAccountName || 'default'}`;

/** Does an RBAC subject cover the ServiceAccount `ns/name`? Includes the service-account groups. */
function covers(s: V1Subject, sa: string, bindingNs?: string): boolean {
  const [ns, name] = sa.split('/') as [string, string];
  if (s.kind === 'ServiceAccount') return s.name === name && (s.namespace ?? bindingNs) === ns;
  if (s.kind === 'Group') return s.name === 'system:serviceaccounts' || s.name === `system:serviceaccounts:${ns}` || s.name === 'system:authenticated';
  return false;
}

export function riskChains(snapshot: ClusterSnapshot, findings: Finding[], excluded: ReadonlySet<string>): RiskChain[] {
  const saAutomount = new Map((snapshot.serviceAccounts ?? []).map((a) => [`${a.metadata?.namespace ?? 'default'}/${a.metadata?.name}`, a.automountServiceAccountToken]));
  // Kubernetes: the pod's automountServiceAccountToken wins; otherwise the ServiceAccount's; otherwise true.
  const tokenMounted = (p: V1Pod) => (p.spec?.automountServiceAccountToken ?? saAutomount.get(saOf(p)) ?? true) !== false;
  const caveat = (sa: string) => (saAutomount.has(sa) ? CAVEAT_NONE : CAVEAT_UNKNOWN_SA);
  const pods = snapshot.pods.filter((p) => !excluded.has(p.metadata?.namespace ?? 'default') && tokenMounted(p));
  // One entry per workload (replicas collapse), keyed by the ServiceAccount whose token it carries.
  const bySa = new Map<string, Map<string, V1Pod>>();
  for (const p of pods) {
    const key = resourceKey(workloadOf(p));
    const m = bySa.get(saOf(p)) ?? new Map<string, V1Pod>();
    if (!m.has(key)) m.set(key, p);
    bySa.set(saOf(p), m);
  }
  // Index once: per-workload and per-binding lookups must stay linear on large clusters (see scripts/bench.mjs).
  const byWorkload = new Map<string, Finding[]>();
  const byBinding = new Map<string, string[]>();
  for (const f of findings) {
    const w = resourceKey({ ...f.resource, container: undefined });
    if (!byWorkload.has(w)) byWorkload.set(w, []);
    byWorkload.get(w)!.push(f);
    if (f.checkId.startsWith('NOIP-RBAC-')) {
      if (!byBinding.has(w)) byBinding.set(w, []);
      byBinding.get(w)!.push(f.id);
    }
  }
  const findingsOn = (workload: string) => byWorkload.get(workload) ?? [];
  const rbacFinding = (kind: string, name: string, ns?: string) => byBinding.get(resourceKey({ kind, namespace: ns, name })) ?? [];

  const chains: RiskChain[] = [];
  // 1. A running workload carries a token that is cluster-admin.
  for (const b of snapshot.clusterRoleBindings) {
    if (b.roleRef.kind !== 'ClusterRole' || b.roleRef.name !== 'cluster-admin') continue;
    for (const [sa, workloads] of bySa) {
      if (!(b.subjects ?? []).some((s) => covers(s, sa))) continue;
      const entries = [...workloads.keys()].sort();
      const hostAccess = entries.flatMap((w) => findingsOn(w).filter((f) => HOST_ACCESS.has(f.checkId)));
      const binding = b.metadata?.name ?? 'unknown';
      chains.push({
        id: `CHAIN-SA-CLUSTER-ADMIN:${sa}:${binding}`,
        severity: 'critical',
        title: `Workloads running as ${sa} carry a cluster-admin token`,
        steps: [
          `${entries.length} workload(s) run as ServiceAccount ${sa} with its token mounted (${entries.slice(0, 3).join(', ')}${entries.length > 3 ? ', …' : ''}).`,
          `ClusterRoleBinding ${binding} grants that ServiceAccount cluster-admin.`,
          hostAccess.length
            ? `At least one of them also has host-level access (${[...new Set(hostAccess.map((f) => f.checkId))].join(', ')}), so the node itself is exposed as well.`
            : 'Code execution in any of them (a vulnerable dependency, an exposed debug endpoint) is enough to control the whole cluster.',
        ],
        entryPoints: entries,
        findingIds: [...new Set([...rbacFinding('ClusterRoleBinding', binding), ...hostAccess.map((f) => f.id)])].sort(),
        caveat: caveat(sa),
      });
    }
  }
  // 2. The namespace's default ServiceAccount has a Role, and workloads without their own ServiceAccount inherit it.
  for (const b of snapshot.roleBindings) {
    const ns = b.metadata?.namespace ?? 'default';
    if (excluded.has(ns)) continue;
    const sa = `${ns}/default`;
    const workloads = bySa.get(sa);
    if (!workloads?.size || !(b.subjects ?? []).some((s) => s.kind === 'ServiceAccount' && covers(s, sa, ns))) continue;
    const entries = [...workloads.keys()].sort();
    const binding = b.metadata?.name ?? 'unknown';
    chains.push({
      id: `CHAIN-DEFAULT-SA-ROLE:${ns}:${binding}`,
      severity: 'medium',
      title: `Every workload in ${ns} without its own ServiceAccount inherits ${b.roleRef.kind} ${b.roleRef.name}`,
      steps: [
        `RoleBinding ${ns}/${binding} grants ${b.roleRef.kind} ${b.roleRef.name} to ServiceAccount ${sa}.`,
        `${entries.length} workload(s) run as ${sa} with its token mounted (${entries.slice(0, 3).join(', ')}${entries.length > 3 ? ', …' : ''}), so each of them holds those permissions, and so will any new workload that doesn't name a ServiceAccount.`,
      ],
      entryPoints: entries,
      findingIds: rbacFinding('RoleBinding', binding, ns),
      caveat: caveat(sa),
    });
  }
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return chains.sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
}
