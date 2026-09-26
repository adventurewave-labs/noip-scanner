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
  /** Reference mappings to NSA/CISA and NIST SP 800-190 guidance (navigation aids, not an attestation). */
  references?: { nsaCisa: string[]; nist800190: string[] };
  /** Deterministic RFC 6902 patch against the resource's own object, when one exists (see src/remediation.ts). */
  fix?: { description: string; patch: Array<{ op: 'add' | 'replace' | 'remove'; path: string; value?: unknown }> };
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

/** Results merged from another scanner's SARIF (`--import-sarif`). Never affect NOIP's score or controls. */
export interface ImportedRun {
  tool: string;
  version?: string;
  inputFile: string;
  inputSha256: string;
  results: Array<{ ruleId: string; severity: Severity; message: string; location?: { uri: string; line?: number } }>;
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
    cluster: {
      serverVersion: string;
      platform?: string;
      context?: string;
      nodeCount: number;
      /** Upstream support status of the control-plane minor version (a fact; never affects the score). */
      versionSupport?: import('./k8s/support.js').VersionSupport;
    };
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
  imported?: ImportedRun[];
  explanation?: Explanation | null;
  /** Accepted-risk findings, each with the suppression that hid it (reason, owner, expiry). */
  suppressed?: Array<{ finding: Finding; suppression: { reason: string; owner: string; expires: string; rule: string } }>;
  /** Which Pod Security level each namespace could enforce today (a planning aid; never affects the score). */
  podSecurity?: import('./psa.js').PodSecurityReadiness;
  /** Findings that compound into an attack path (e.g. a running workload carrying a cluster-admin token). Not scored. */
  riskChains?: import('./chains.js').RiskChain[];
  /** Non-fatal notices, e.g. expired or stale suppressions. */
  warnings?: string[];
}
