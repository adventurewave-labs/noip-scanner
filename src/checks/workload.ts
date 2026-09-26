import type { V1Container, V1Pod } from '@kubernetes/client-node';
import type { ResourceRef } from '../types.js';

/**
 * Attribute a pod to the workload that owns it so N replicas produce one finding, not N.
 * ReplicaSet -> Deployment is resolved via the pod-template-hash suffix, which is exact for
 * Deployment-managed ReplicaSets and left alone otherwise.
 */
export function workloadOf(pod: V1Pod): ResourceRef {
  const ns = pod.metadata?.namespace ?? 'default';
  const owner = pod.metadata?.ownerReferences?.find((o) => o.controller) ?? pod.metadata?.ownerReferences?.[0];
  if (owner) {
    if (owner.kind === 'ReplicaSet') {
      const hash = pod.metadata?.labels?.['pod-template-hash'];
      if (hash && owner.name.endsWith(`-${hash}`)) {
        return { kind: 'Deployment', namespace: ns, name: owner.name.slice(0, -(hash.length + 1)) };
      }
      return { kind: 'ReplicaSet', namespace: ns, name: owner.name };
    }
    if (['StatefulSet', 'DaemonSet', 'Job', 'ReplicationController'].includes(owner.kind)) {
      return { kind: owner.kind, namespace: ns, name: owner.name };
    }
  }
  return { kind: 'Pod', namespace: ns, name: pod.metadata?.name ?? 'unknown' };
}

export interface ContainerSite {
  container: V1Container;
  /** JSON-ish path prefix used in evidence, e.g. `spec.initContainers[migrate]`. */
  path: string;
}

export function containersOf(pod: V1Pod): ContainerSite[] {
  return [
    ...(pod.spec?.initContainers ?? []).map((c) => ({ container: c, path: `spec.initContainers[${c.name}]` })),
    ...(pod.spec?.containers ?? []).map((c) => ({ container: c, path: `spec.containers[${c.name}]` })),
  ];
}

export function inScope(ns: string | undefined, excluded: ReadonlySet<string>): boolean {
  return !excluded.has(ns ?? 'default');
}
