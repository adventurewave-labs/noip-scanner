import { SEVERITIES, type Finding, type Report, type Severity } from '../types.js';

/**
 * Deterministic "fix these first" ordering for an executive summary. No LLM: findings are grouped by
 * check, then ranked by severity, blast radius (cluster-wide > namespace > workload) and how many
 * resources are affected. Ties break on check id so the order is stable.
 */
export interface Priority {
  checkId: string;
  title: string;
  severity: Severity;
  resources: number;
  scope: 'cluster' | 'namespace' | 'workload';
  autoFixable: number;
  sample: string[];
}

export interface ExecutiveSummary {
  headline: string;
  /** Number of checks with at least one finding (used by localised headlines). */
  failedChecks: number;
  priorities: Priority[];
  quickWins: number;
  needsDesign: number;
}

const SCOPE_RANK = { cluster: 0, namespace: 1, workload: 2 } as const;
const scopeOf = (f: Finding): Priority['scope'] =>
  f.resource.kind === 'ClusterRoleBinding' ? 'cluster' : f.resource.kind === 'Namespace' || f.resource.kind === 'RoleBinding' ? 'namespace' : 'workload';

export function executiveSummary(r: Report, top = 5): ExecutiveSummary {
  const groups = new Map<string, Finding[]>();
  for (const f of r.findings) groups.set(f.checkId, [...(groups.get(f.checkId) ?? []), f]);
  const priorities: Priority[] = [...groups.values()]
    .map((fs) => {
      const f = fs[0]!;
      const scope = fs.map(scopeOf).sort((a, b) => SCOPE_RANK[a] - SCOPE_RANK[b])[0]!;
      return {
        checkId: f.checkId,
        title: f.title,
        severity: f.severity,
        resources: fs.length,
        scope,
        autoFixable: fs.filter((x) => x.fix).length,
        sample: [...new Set(fs.map((x) => [x.resource.kind, x.resource.namespace, x.resource.name].filter(Boolean).join('/')))].slice(0, 3),
      };
    })
    .sort(
      (a, b) =>
        SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
        SCOPE_RANK[a.scope] - SCOPE_RANK[b.scope] ||
        b.resources - a.resources ||
        a.checkId.localeCompare(b.checkId),
    );
  const quickWins = r.findings.filter((f) => f.fix).length;
  const { critical, high } = r.summary.bySeverity;
  const headline =
    r.findings.length === 0
      ? `No findings across ${r.provenance.checksRun.length} checks. Score ${r.summary.score}/100.`
      : `Score ${r.summary.score}/100. ${r.findings.length} finding(s) (${critical} critical, ${high} high) from ${priorities.length} of ${r.provenance.checksRun.length} checks; ` +
        `${quickWins} have a deterministic fix.`;
  return { headline, failedChecks: priorities.length, priorities: priorities.slice(0, top), quickWins, needsDesign: r.findings.length - quickWins };
}
