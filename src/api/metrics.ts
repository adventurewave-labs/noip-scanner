import { SEVERITIES, type Report } from '../types.js';

/**
 * Prometheus text exposition (format 0.0.4) of the latest scan. Pure: renders a report plus scrape state.
 * The API caches the scan for NOIP_METRICS_TTL seconds, so a Prometheus scrape interval does not become a
 * full cluster list every 15 seconds.
 */
export const METRICS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

/** Label values: escape backslash, double quote and newline, per the exposition format. */
export const labelValue = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
const labels = (l: Record<string, string>) => {
  const e = Object.entries(l);
  return e.length ? `{${e.map(([k, v]) => `${k}="${labelValue(v)}"`).join(',')}}` : '';
};

const PSA_RANK = { privileged: 0, baseline: 1, restricted: 2 } as const;

export interface ScrapeState {
  /** Whether the most recent scan attempt succeeded. */
  up: boolean;
  /** Seconds the most recent successful scan took. */
  durationSeconds?: number;
  /** Error class of the most recent failed attempt, e.g. K8sUnavailable. */
  lastError?: string;
}

export function renderMetrics(r: Report | undefined, state: ScrapeState): string {
  const out: string[] = [];
  const metric = (name: string, type: 'gauge' | 'counter', help: string, samples: Array<[Record<string, string>, number]>) => {
    out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
    for (const [l, v] of samples) out.push(`${name}${labels(l)} ${Number.isFinite(v) ? v : 'NaN'}`);
  };
  metric('noip_up', 'gauge', 'Whether the most recent scan attempt succeeded (1) or failed (0).', [[state.lastError ? { error: state.lastError } : {}, state.up ? 1 : 0]]);
  if (!r) return out.join('\n') + '\n';

  metric('noip_info', 'gauge', 'Scanner and target of the last successful scan.', [
    [{ version: r.provenance.scanner.version, git_sha: r.provenance.scanner.gitSha, source: r.source, context: r.provenance.cluster.context ?? '', server_version: r.provenance.cluster.serverVersion }, 1],
  ]);
  metric('noip_last_scan_timestamp_seconds', 'gauge', 'Unix time of the last successful scan.', [[{}, Math.floor(Date.parse(r.provenance.scannedAt) / 1000)]]);
  if (state.durationSeconds !== undefined) metric('noip_scan_duration_seconds', 'gauge', 'Duration of the last successful scan.', [[{}, state.durationSeconds]]);
  metric('noip_posture_score', 'gauge', 'Posture score, 0-100 (share of check weight passing).', [[{}, r.summary.score]]);
  metric('noip_findings', 'gauge', 'Reported findings by severity (suppressed findings excluded).', SEVERITIES.map((s) => [{ severity: s }, r.summary.bySeverity[s]]));
  metric('noip_suppressed_findings', 'gauge', 'Findings hidden by a live accepted-risk suppression.', [[{}, r.summary.suppressed]]);
  const failed = new Set(r.findings.map((f) => f.checkId));
  const sev = new Map(r.findings.map((f) => [f.checkId, f.severity]));
  metric(
    'noip_check_failed',
    'gauge',
    'Whether each check that ran has at least one finding (1) or none (0).',
    r.provenance.checksRun.map((c) => [{ check: c, ...(sev.has(c) ? { severity: sev.get(c)! } : {}) }, failed.has(c) ? 1 : 0]),
  );
  metric('noip_controls_failed', 'gauge', 'Mapped CIS controls with at least one finding.', [[{}, r.summary.controlsFailed]]);
  if (r.provenance.cluster.versionSupport?.daysLeft !== undefined) {
    metric('noip_kubernetes_support_days_left', 'gauge', 'Days until upstream end of life of the control-plane minor version (negative: past).', [
      [{ minor: r.provenance.cluster.versionSupport.minor }, r.provenance.cluster.versionSupport.daysLeft],
    ]);
  }
  if (r.podSecurity?.namespaces.length) {
    metric(
      'noip_namespace_pod_security_level',
      'gauge',
      'Highest Pod Security level each namespace could enforce today: 0 privileged, 1 baseline, 2 restricted.',
      r.podSecurity.namespaces.map((n) => [{ namespace: n.namespace }, PSA_RANK[n.canEnforce]]),
    );
  }
  return out.join('\n') + '\n';
}
