import type { Report } from '../types.js';

/** Keys whose values never leave the process, wherever they appear. */
export const DROP_KEYS = new Set(['env', 'envFrom', 'annotations', 'data', 'stringData', 'binaryData', 'value', 'managedFields', 'token', 'password', 'secret']);

const SCRUB_PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '[REDACTED:PEM]'],
  // base64url segments may end in `-`/`_`, so use explicit token boundaries, not \b (found by fuzzing)
  [/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g, '[REDACTED:JWT]'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED:AWS_KEY]'],
  [/(?<![A-Za-z0-9_-])(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])/g, '[REDACTED:API_KEY]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED:GITHUB_TOKEN]'],
  [/\b[Bb]earer\s+[A-Za-z0-9._~+/-]{12,}=*/g, 'Bearer [REDACTED]'],
  [/((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;'"]+/gi, '$1[REDACTED]'],
];

export function scrubString(s: string): string {
  return SCRUB_PATTERNS.reduce((acc, [re, rep]) => acc.replace(re, rep), s);
}

/** Deep copy with DROP_KEYS removed and every string scrubbed. Works on any JSON-shaped value. */
export function redact<T>(value: T): T {
  if (typeof value === 'string') return scrubString(value) as T;
  if (Array.isArray(value)) return value.map((v) => redact(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (DROP_KEYS.has(k)) continue;
      out[k] = redact(v);
    }
    return out as T;
  }
  return value;
}

/**
 * The only thing ever sent to an LLM: a minimal projection of the deterministic report,
 * then passed through redact(). Raw Kubernetes objects are never included.
 */
export function llmPayload(report: Report) {
  return redact({
    source: report.source,
    kubernetesVersion: report.provenance.cluster.serverVersion,
    summary: report.summary,
    findings: report.findings.slice(0, 60).map((f) => ({
      findingId: f.id,
      checkId: f.checkId,
      severity: f.severity,
      title: f.title,
      evidence: f.evidence,
      controls: f.controls,
    })),
    truncatedFindings: Math.max(0, report.findings.length - 60),
    failedControls: report.controls.filter((c) => c.status === 'fail').map((c) => ({ id: c.id, title: c.title })),
    // Deterministic context the model should weigh, not re-derive: compounding findings and safe PSA levels.
    riskChains: (report.riskChains ?? []).slice(0, 10).map((c) => ({ severity: c.severity, title: c.title, findingIds: c.findingIds })),
    podSecurity: (report.podSecurity?.namespaces ?? []).slice(0, 50).map((n) => ({ namespace: n.namespace, enforcedNow: n.enforce ?? null, couldEnforce: n.canEnforce, blockingWorkloads: n.blockers.length })),
  });
}
