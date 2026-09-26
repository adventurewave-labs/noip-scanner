import type {
  V1ClusterRoleBinding,
  V1Namespace,
  V1NetworkPolicy,
  V1Pod,
  V1RoleBinding,
} from '@kubernetes/client-node';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

/** live = Kubernetes API; demo = bundled fixture; manifests = offline YAML (shift-left). */
export type DataSource = 'live' | 'demo' | 'manifests';

/** Everything a scan needs, fetched once per scan (see src/k8s/snapshot.ts). */
export interface ClusterSnapshot {
  serverVersion: { gitVersion: string; platform?: string };
  context?: string;
  nodeCount: number;
  namespaces: V1Namespace[];
  pods: V1Pod[];
  networkPolicies: V1NetworkPolicy[];
  clusterRoleBindings: V1ClusterRoleBinding[];
  roleBindings: V1RoleBinding[];
  /** Manifest scans only: `Kind/namespace/name` (or `Kind/name`) -> where it was declared. */
  sources?: Record<string, { file: string; line?: number }>;
}

export interface ResourceRef {
  kind: string;
  name: string;
  namespace?: string;
  container?: string;
  /** Set for offline manifest scans: where the object was declared. */
  source?: { file: string; line?: number };
}

export interface Finding {
  /** Stable identity: `<checkId>:<Kind>/<namespace>/<name>[/<container>]`. */
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  category: string;
  resource: ResourceRef;
  /** One concrete, human-readable line citing the offending field and value. Never contains secret values. */
  evidence: string;
  remediation: string;
  controls: string[];
}

export interface ControlResult {
  id: string;
  title: string;
  benchmark: string;
  status: 'pass' | 'fail';
  findingIds: string[];
  referenceMappings: { soc2: string[]; hipaa: string[] };
}

export interface NetworkSection {
  source: 'k8s-netinspect';
  toolVersion?: string;
  cni?: string;
  inputSha256: string;
  checks: Array<{ name: string; status: 'pass' | 'warn' | 'fail' | 'info'; detail?: string; resource?: string }>;
}

export interface Explanation {
  summary: string;
  priorities: Array<{ findingId: string; why: string; fix: string }>;
  caveats: string[];
}

export interface Report {
  schemaVersion: '1';
  source: DataSource;
  provenance: {
    scanner: { name: 'noip'; version: string; gitSha: string };
    cluster: { serverVersion: string; platform?: string; context?: string; nodeCount: number };
    scannedAt: string;
    checksRun: string[];
    excludedNamespaces: string[];
    /** Present when findings below this severity were filtered out (controls then reflect only the kept findings). */
    minSeverity?: Severity;
  };
  summary: {
    score: number;
    findings: number;
    bySeverity: Record<Severity, number>;
    checksFailed: number;
    controlsFailed: number;
    /** Findings hidden by a live suppression (accepted risk). Not counted anywhere else in the summary. */
    suppressed: number;
  };
  findings: Finding[];
  controls: ControlResult[];
  mappingDisclaimer: string;
  network?: NetworkSection;
  explanation?: Explanation | null;
  /** Accepted-risk findings, each with the suppression that hid it (reason, owner, expiry). */
  suppressed?: Array<{ finding: Finding; suppression: { reason: string; owner: string; expires: string; rule: string } }>;
  /** Non-fatal notices, e.g. expired or stale suppressions. */
  warnings?: string[];
}
