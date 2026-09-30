import type { ClusterSnapshot, ResourceRef, Severity } from '../types.js';

export interface CheckContext {
  /** Namespaces skipped by workload and namespace checks (cluster-scoped RBAC checks still run). */
  excludedNamespaces: ReadonlySet<string>;
}

export interface RawFinding {
  resource: ResourceRef;
  evidence: string;
}

/** A check is a pure function over an already-fetched snapshot. No I/O. */
export interface Check {
  id: string;
  title: string;
  severity: Severity;
  category: 'Pod Security' | 'Network' | 'RBAC' | 'Secrets';
  /** CIS Kubernetes Benchmark control IDs this check provides evidence for. */
  controls: string[];
  remediation: string;
  run(snapshot: ClusterSnapshot, ctx: CheckContext): RawFinding[];
}

export const SYSTEM_NAMESPACES = ['kube-system', 'kube-public', 'kube-node-lease'] as const;
