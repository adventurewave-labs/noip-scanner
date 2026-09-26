import type { V1Container, V1Pod } from '@kubernetes/client-node';
import { workloadOf } from './checks/workload.js';
import { resourceKey } from './scan.js';
import type { ClusterSnapshot, Finding } from './types.js';

/**
 * Deterministic fixes as RFC 6902 JSON Patch operations against the finding's own object
 * (the Pod, Deployment, CronJob, Namespace…). Only fixes that need no human judgement are
 * generated; limits, secret mounts, RBAC and NetworkPolicy design stay advisory.
 */
export type PatchOp = { op: 'add' | 'replace' | 'remove'; path: string; value?: unknown };
export interface Fix {
  description: string;
  patch: PatchOp[];
}

const POD_SPEC_PREFIX: Record<string, string> = {
  Pod: '/spec',
  Deployment: '/spec/template/spec',
  StatefulSet: '/spec/template/spec',
  DaemonSet: '/spec/template/spec',
  ReplicaSet: '/spec/template/spec',
  ReplicationController: '/spec/template/spec',
  Job: '/spec/template/spec',
  CronJob: '/spec/jobTemplate/spec/template/spec',
};

const ptr = (s: string) => s.replace(/~/g, '~0').replace(/\//g, '~1');

/** Set one securityContext field, creating securityContext if the container has none. */
function scField(base: string, c: V1Container, field: string, value: unknown): PatchOp[] {
  if (!c.securityContext) return [{ op: 'add', path: `${base}/securityContext`, value: { [field]: value } }];
  const has = (c.securityContext as Record<string, unknown>)[field] !== undefined;
  return [{ op: has ? 'replace' : 'add', path: `${base}/securityContext/${field}`, value }];
}

function locate(f: Finding, byWorkload: Map<string, V1Pod>): { pod: V1Pod; prefix: string } | undefined {
  const prefix = POD_SPEC_PREFIX[f.resource.kind];
  const pod = byWorkload.get(resourceKey({ kind: f.resource.kind, namespace: f.resource.namespace, name: f.resource.name }));
  return prefix && pod ? { pod, prefix } : undefined;
}

function containerSite(pod: V1Pod, prefix: string, name?: string): { c: V1Container; base: string } | undefined {
  for (const list of ['containers', 'initContainers'] as const) {
    const i = (pod.spec?.[list] ?? []).findIndex((c) => c.name === name);
    if (i >= 0) return { c: pod.spec![list]![i]!, base: `${prefix}/${list}/${i}` };
  }
  return undefined; // ephemeral containers cannot be patched declaratively
}

export function fixFor(f: Finding, byWorkload: Map<string, V1Pod>, nsHasLabels: (name: string) => boolean): Fix | undefined {
  if (f.checkId === 'NOIP-NS-001') {
    const key = 'pod-security.kubernetes.io/enforce';
    return {
      description: 'Enforce the restricted Pod Security Standard on this namespace (dry-run with the warn label first).',
      // RFC 6902 `add` needs the parent to exist: create the labels map when the namespace has none.
      patch: nsHasLabels(f.resource.name)
        ? [{ op: 'add', path: `/metadata/labels/${ptr(key)}`, value: 'restricted' }]
        : [{ op: 'add', path: '/metadata/labels', value: { [key]: 'restricted' } }],
    };
  }
  const loc = locate(f, byWorkload);
  if (!loc) return undefined;
  const { pod, prefix } = loc;
  switch (f.checkId) {
    case 'NOIP-POD-002':
    case 'NOIP-POD-003':
    case 'NOIP-POD-004': {
      const field = { 'NOIP-POD-002': 'hostPID', 'NOIP-POD-003': 'hostIPC', 'NOIP-POD-004': 'hostNetwork' }[f.checkId];
      return { description: `Remove ${field} from the pod spec.`, patch: [{ op: 'remove', path: `${prefix}/${field}` }] };
    }
  }
  const site = containerSite(pod, prefix, f.resource.container);
  if (!site) return undefined;
  const { c, base } = site;
  switch (f.checkId) {
    case 'NOIP-POD-001':
      return { description: `Run container ${c.name} unprivileged.`, patch: scField(base, c, 'privileged', false) };
    case 'NOIP-POD-005':
      // privileged:true forces escalation on; the API rejects the combination, so fix both.
      return {
        description: `Disable privilege escalation for container ${c.name}.`,
        patch: c.securityContext?.privileged ? [{ op: 'replace', path: `${base}/securityContext/privileged`, value: false }, ...scField(base, c, 'allowPrivilegeEscalation', false)] : scField(base, c, 'allowPrivilegeEscalation', false),
      };
    case 'NOIP-POD-006':
      return { description: `Require a non-root user for container ${c.name} (the image must support it).`, patch: scField(base, c, 'runAsNonRoot', true) };
    case 'NOIP-POD-007':
      return { description: `Make the root filesystem of container ${c.name} read-only (add emptyDir mounts for writable paths if needed).`, patch: scField(base, c, 'readOnlyRootFilesystem', true) };
    default:
      return undefined;
  }
}

/** Attach `fix` to every finding that has a deterministic remediation. */
export function attachFixes(findings: Finding[], snapshot: ClusterSnapshot): void {
  const byWorkload = new Map<string, V1Pod>();
  for (const p of snapshot.pods) {
    const key = resourceKey(workloadOf(p));
    if (!byWorkload.has(key)) byWorkload.set(key, p);
  }
  const labelled = new Map(snapshot.namespaces.map((n) => [n.metadata?.name, Boolean(n.metadata?.labels)]));
  for (const f of findings) {
    const fx = fixFor(f, byWorkload, (name) => labelled.get(name) ?? false);
    if (fx) f.fix = fx;
  }
  // Several findings on one container that has no securityContext each `add` the whole object; applied in
  // sequence the last would overwrite the others. Give every such op the union of all fields, so applying
  // any subset, in any order, yields every fix.
  const union = new Map<string, Record<string, unknown>>();
  const ops = findings.flatMap((f) => f.fix?.patch ?? []).filter((o) => o.op === 'add' && o.path.endsWith('/securityContext') && typeof o.value === 'object');
  for (const o of ops) union.set(o.path, { ...union.get(o.path), ...(o.value as Record<string, unknown>) });
  for (const o of ops) o.value = { ...union.get(o.path) };
}
