import { SEVERITIES, type Finding, type Report, type Severity } from '../types.js';

/**
 * Posture drift between two reports (e.g. last month's retainer scan vs today's).
 * Findings are matched by their stable id, so a renamed workload shows as resolved + new.
 */
export interface ReportDiff {
  from: { scannedAt: string; source: string; score: number; gitSha: string };
  to: { scannedAt: string; source: string; score: number; gitSha: string };
  scoreDelta: number;
  new: Finding[];
  resolved: Finding[];
  unchanged: number;
  /** Same id, different evidence (e.g. a different secret key now exposed). */
  changed: Array<{ id: string; before: string; after: string }>;
  newlySuppressed: string[];
  controls: Array<{ id: string; from: 'pass' | 'fail'; to: 'pass' | 'fail' }>;
  checksAdded: string[];
  checksRemoved: string[];
  warnings: string[];
}

export function diffReports(a: Report, b: Report): ReportDiff {
  const A = new Map(a.findings.map((f) => [f.id, f]));
  const B = new Map(b.findings.map((f) => [f.id, f]));
  const sev = (f: Finding) => SEVERITIES.indexOf(f.severity);
  const bySev = (x: Finding, y: Finding) => sev(x) - sev(y) || x.id.localeCompare(y.id);
  const aSup = new Set((a.suppressed ?? []).map((x) => x.finding.id));
  const bSup = new Set((b.suppressed ?? []).map((x) => x.finding.id));
  const aChecks = new Set(a.provenance.checksRun);
  const bChecks = new Set(b.provenance.checksRun);
  const aCtl = new Map(a.controls.map((c) => [c.id, c.status]));

  const warnings: string[] = [];
  if (a.source !== b.source) warnings.push(`comparing a ${a.source} report with a ${b.source} report`);
  if (a.provenance.cluster.context !== b.provenance.cluster.context) {
    warnings.push(`different targets: ${a.provenance.cluster.context ?? 'n/a'} vs ${b.provenance.cluster.context ?? 'n/a'}`);
  }
  if (a.provenance.excludedNamespaces.join() !== b.provenance.excludedNamespaces.join()) warnings.push('excluded namespaces differ between the two scans');

  return {
    from: { scannedAt: a.provenance.scannedAt, source: a.source, score: a.summary.score, gitSha: a.provenance.scanner.gitSha },
    to: { scannedAt: b.provenance.scannedAt, source: b.source, score: b.summary.score, gitSha: b.provenance.scanner.gitSha },
    scoreDelta: b.summary.score - a.summary.score,
    // A finding that moved to "suppressed" is not "resolved"; it is accepted risk and is listed separately.
    new: [...B.values()].filter((f) => !A.has(f.id)).sort(bySev),
    resolved: [...A.values()].filter((f) => !B.has(f.id) && !bSup.has(f.id)).sort(bySev),
    unchanged: [...B.keys()].filter((id) => A.has(id)).length,
    changed: [...B.values()].filter((f) => A.has(f.id) && A.get(f.id)!.evidence !== f.evidence).map((f) => ({ id: f.id, before: A.get(f.id)!.evidence, after: f.evidence })),
    newlySuppressed: [...bSup].filter((id) => !aSup.has(id)).sort(),
    controls: b.controls.filter((c) => aCtl.has(c.id) && aCtl.get(c.id) !== c.status).map((c) => ({ id: c.id, from: aCtl.get(c.id)!, to: c.status })),
    checksAdded: [...bChecks].filter((c) => !aChecks.has(c)),
    checksRemoved: [...aChecks].filter((c) => !bChecks.has(c)),
    warnings,
  };
}

/** True when `to` has a new finding at or above `severity`. */
export function regressed(d: ReportDiff, severity: Severity): boolean {
  const limit = SEVERITIES.indexOf(severity);
  return d.new.some((f) => SEVERITIES.indexOf(f.severity) <= limit);
}

export function renderDiffMarkdown(d: ReportDiff): string {
  const sign = (n: number) => (n > 0 ? `+${n}` : String(n));
  const line = (f: Finding) => `- [${f.severity.toUpperCase()}] \`${f.id}\` — ${f.evidence}`;
  const out = [
    '# NOIP posture drift',
    '',
    `From ${d.from.scannedAt} (${d.from.source}, score ${d.from.score}) to ${d.to.scannedAt} (${d.to.source}, score ${d.to.score}): **score ${sign(d.scoreDelta)}**, ` +
      `${d.new.length} new, ${d.resolved.length} resolved, ${d.unchanged} unchanged, ${d.newlySuppressed.length} newly suppressed.`,
    '',
  ];
  if (d.warnings.length) out.push(...d.warnings.map((w) => `> ⚠️ ${w}`), '');
  out.push('## New findings', '', ...(d.new.length ? d.new.map(line) : ['None.']), '');
  out.push('## Resolved', '', ...(d.resolved.length ? d.resolved.map(line) : ['None.']), '');
  if (d.changed.length) out.push('## Changed evidence', '', ...d.changed.map((c) => `- \`${c.id}\`: ${c.before} → ${c.after}`), '');
  if (d.newlySuppressed.length) out.push('## Newly suppressed (accepted risk)', '', ...d.newlySuppressed.map((id) => `- \`${id}\``), '');
  if (d.controls.length) out.push('## Control status changes', '', ...d.controls.map((c) => `- ${c.id}: ${c.from} → ${c.to}`), '');
  if (d.checksAdded.length || d.checksRemoved.length) {
    out.push('## Check set changed', '', `Added: ${d.checksAdded.join(', ') || '—'} · Removed: ${d.checksRemoved.join(', ') || '—'}`, '');
  }
  return out.join('\n');
}
