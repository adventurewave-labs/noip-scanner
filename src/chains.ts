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

/** The deprecated `serviceAccount` field is honoured too, as the API server does (manifest scans see it raw). */
const saOf = (p: V1Pod) => `${p.metadata?.namespace ?? 'default'}/${p.spec?.serviceAccountName || p.spec?.serviceAccount || 'default'}`;
/** Finished pods (Job pods that Succeeded/Failed) no longer run anything. */
const running = (p: V1Pod) => p.status?.phase !== 'Succeeded' && p.status?.phase !== 'Failed';

/** Does an RBAC subject cover the ServiceAccount `ns/name`? Includes the service-account groups. */
function covers(s: V1Subject, sa: string, bindingNs?: string): boolean {
  const [ns, name] = sa.split('/') as [string, string];
  if (s.kind === 'ServiceAccount') return s.name === name && (s.namespace ?? bindingNs) === ns;
  // Kubernetes authenticates a ServiceAccount as the user system:serviceaccount:<ns>:<name>.
  if (s.kind === 'User') return s.name === `system:serviceaccount:${ns}:${name}`;
  if (s.kind === 'Group') return s.name === 'system:serviceaccounts' || s.name === `system:serviceaccounts:${ns}` || s.name === 'system:authenticated';
  return false;
}

export function riskChains(snapshot: ClusterSnapshot, findings: Finding[], excluded: ReadonlySet<string>): RiskChain[] {
  const saAutomount = new Map((snapshot.serviceAccounts ?? []).map((a) => [`${a.metadata?.namespace ?? 'default'}/${a.metadata?.name}`, a.automountServiceAccountToken]));
  // Kubernetes: the pod's automountServiceAccountToken wins; otherwise the ServiceAccount's; otherwise true.
  const tokenMounted = (p: V1Pod) => (p.spec?.automountServiceAccountToken ?? saAutomount.get(saOf(p)) ?? true) !== false;
  const caveat = (sa: string) => (saAutomount.has(sa) ? CAVEAT_NONE : CAVEAT_UNKNOWN_SA);
  const pods = snapshot.pods.filter((p) => !excluded.has(p.metadata?.namespace ?? 'default') && running(p) && tokenMounted(p));
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

  // Externally reachable Services -> the workloads their selectors match (in scope, running).
  const EXTERNAL = new Set(['LoadBalancer', 'NodePort']);
  const exposure = new Map<string, Set<string>>();
  const serviceType = new Map<string, string>();
  const exposedBy = new Map<string, string[]>(); // workload -> exposing services
  const podsByNs = new Map<string, V1Pod[]>(); // group once: exposure stays linear in Services + pods
  for (const p of snapshot.pods) {
    if (!running(p)) continue;
    const ns = p.metadata?.namespace ?? 'default';
    if (!podsByNs.has(ns)) podsByNs.set(ns, []);
    podsByNs.get(ns)!.push(p);
  }
  for (const svc of snapshot.services ?? []) {
    const type = svc.spec?.type ?? 'ClusterIP';
    const selector = svc.spec?.selector ?? {};
    if ((!EXTERNAL.has(type) && !svc.spec?.externalIPs?.length) || !Object.keys(selector).length) continue;
    const ns = svc.metadata?.namespace ?? 'default';
    const key = `${ns}/${svc.metadata?.name ?? 'unknown'}`;
    serviceType.set(key, svc.spec?.externalIPs?.length && !EXTERNAL.has(type) ? `${type} with externalIPs` : type);
    const hits = new Set<string>();
    for (const p of podsByNs.get(ns) ?? []) {
      const labels = p.metadata?.labels ?? {};
      if (Object.entries(selector).every(([k, v]) => labels[k] === v)) {
        const w = resourceKey(workloadOf(p));
        hits.add(w);
        if (!exposedBy.has(w)) exposedBy.set(w, []);
        if (!exposedBy.get(w)!.includes(key)) exposedBy.get(w)!.push(key);
      }
    }
    if (hits.size) exposure.set(key, hits);
  }

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
            ? `At least one of them also shares host namespaces or privileges (${[...new Set(hostAccess.map((f) => f.checkId))].join(', ')}), widening what a compromise of it reaches on the node.`
            : 'Code execution in any of them (a vulnerable dependency, an exposed debug endpoint) is enough to control the whole cluster.',
          ...(() => {
            const ex = entries.filter((w) => exposedBy.has(w));
            const via = [...new Set(ex.flatMap((w) => exposedBy.get(w)!))].sort();
            return ex.length ? [`${ex.join(', ')} ${ex.length === 1 ? 'is' : 'are'} exposed outside the cluster (Service${via.length > 1 ? 's' : ''} ${via.join(', ')}), so the first step may need no foothold.`] : [];
          })(),
        ],
        entryPoints: entries,
        findingIds: [...new Set([...rbacFinding('ClusterRoleBinding', binding), ...hostAccess.map((f) => f.id)])].sort(),
        caveat: caveat(sa),
      });
    }
  }
  // 2. A default ServiceAccount has a Role (or ClusterRole via a RoleBinding), and workloads without their own
  //    ServiceAccount inherit it. The subject may be another namespace's default SA (a cross-namespace grant).
  const BROAD = new Set(['cluster-admin', 'admin', 'edit']);
  for (const b of snapshot.roleBindings) {
    const ns = b.metadata?.namespace ?? 'default';
    if (excluded.has(ns)) continue;
    const binding = b.metadata?.name ?? 'unknown';
    const sas = [...new Set((b.subjects ?? []).filter((s) => s.kind === 'ServiceAccount' && s.name === 'default').map((s) => `${s.namespace ?? ns}/default`))];
    for (const sa of sas.sort()) {
      const workloads = bySa.get(sa);
      if (!workloads?.size) continue;
      const entries = [...workloads.keys()].sort();
      const saNs = sa.split('/')[0]!;
      const broad = b.roleRef.kind === 'ClusterRole' && BROAD.has(b.roleRef.name);
      chains.push({
        id: `CHAIN-DEFAULT-SA-ROLE:${ns}:${binding}${saNs === ns ? '' : `:${saNs}`}`,
        severity: broad ? 'high' : 'medium',
        title: `Every workload in ${saNs} without its own ServiceAccount inherits ${b.roleRef.kind} ${b.roleRef.name}${saNs === ns ? '' : ` in namespace ${ns}`}`,
        steps: [
          `RoleBinding ${ns}/${binding} grants ${b.roleRef.kind} ${b.roleRef.name} in namespace ${ns} to ServiceAccount ${sa}${broad ? ` (${b.roleRef.name} is a broad built-in role)` : ''}.`,
          `${entries.length} workload(s) run as ${sa} with its token mounted (${entries.slice(0, 3).join(', ')}${entries.length > 3 ? ', …' : ''}), so each of them holds those permissions, and so will any new workload in ${saNs} that doesn't name a ServiceAccount.`,
        ],
        entryPoints: entries,
        findingIds: rbacFinding('RoleBinding', binding, ns),
        caveat: caveat(sa),
      });
    }
  }
  // 3. A workload with host namespaces or privileges is reachable from outside the cluster through a Service.
  for (const [svc, exposed] of exposure) {
    const [ns] = svc.split('/') as [string, string];
    if (excluded.has(ns)) continue;
    const risky = [...exposed].filter((w) => findingsOn(w).some((f) => HOST_ACCESS.has(f.checkId))).sort();
    if (!risky.length) continue;
    const found = risky.flatMap((w) => findingsOn(w).filter((f) => HOST_ACCESS.has(f.checkId)));
    const checks = [...new Set(found.map((f) => f.checkId))].sort();
    const severe = checks.some((c) => c !== 'NOIP-POD-004'); // privileged or hostPID, not only hostNetwork
    chains.push({
      id: `CHAIN-EXPOSED-HOST-ACCESS:${svc}`,
      severity: severe ? 'critical' : 'high',
      title: `${serviceType.get(svc)} Service ${svc} exposes workloads that share host namespaces or privileges`,
      steps: [
        `Service ${svc} (type ${serviceType.get(svc)}) is exposed outside the cluster and selects ${risky.join(', ')}.`,
        `${risky.length === 1 ? 'That workload' : 'Those workloads'} ${severe ? 'can reach host processes or devices' : "share the node's network namespace"} (${checks.join(', ')}), so a remote exploit of the exposed port lands with host-level reach.`,
      ],
      entryPoints: risky,
      findingIds: [...new Set(found.map((f) => f.id))].sort(),
      caveat:
        'Exposure is judged from Service type (LoadBalancer, NodePort) or externalIPs and label selectors. Internal load-balancer annotations, loadBalancerSourceRanges, Ingress, Gateway and NetworkPolicy are not evaluated, so an internal-only load balancer is still listed.',
    });
  }
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return chains.sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
}
