import { SEVERITIES, type Finding, type Report, type Severity } from '../types.js';
import { code, mdSafe } from './markdown.js';

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
  /** Risk chains that appeared or disappeared (matched by id). */
  chains: { new: Array<{ id: string; severity: Severity; title: string }>; resolved: Array<{ id: string; severity: Severity; title: string }> };
  /** Namespaces whose achievable Pod Security level changed (present in both reports). */
  podSecurity: Array<{ namespace: string; from: string; to: string }>;
  /** Container images that appeared in or disappeared from the inventory. */
  images: { added: string[]; removed: string[] };
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

  const aChains = new Set((a.riskChains ?? []).map((c) => c.id));
  const bChains = new Set((b.riskChains ?? []).map((c) => c.id));
  const chainRef = (c: { id: string; severity: Severity; title: string }) => ({ id: c.id, severity: c.severity, title: c.title });
  const aPsa = new Map((a.podSecurity?.namespaces ?? []).map((n) => [n.namespace, n.canEnforce as string]));
  const aImg = new Set((a.inventory?.images ?? []).map((i) => i.image));
  const bImg = new Set((b.inventory?.images ?? []).map((i) => i.image));

  const warnings: string[] = [];
  if (a.source !== b.source) warnings.push(`comparing a ${a.source} report with a ${b.source} report`);
  if (a.provenance.cluster.context !== b.provenance.cluster.context) {
    warnings.push(`different targets: ${a.provenance.cluster.context ?? 'n/a'} vs ${b.provenance.cluster.context ?? 'n/a'}`);
  }
  if (a.provenance.excludedNamespaces.join() !== b.provenance.excludedNamespaces.join()) warnings.push('excluded namespaces differ between the two scans');
  if ((a.provenance.minSeverity ?? 'low') !== (b.provenance.minSeverity ?? 'low')) {
    warnings.push(`severity filter differs (${a.provenance.minSeverity ?? 'none'} vs ${b.provenance.minSeverity ?? 'none'}): findings below the earlier filter show as new`);
  }

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
    chains: {
      new: (b.riskChains ?? []).filter((c) => !aChains.has(c.id)).map(chainRef),
      resolved: (a.riskChains ?? []).filter((c) => !bChains.has(c.id)).map(chainRef),
    },
    podSecurity: (b.podSecurity?.namespaces ?? [])
      .filter((n) => aPsa.has(n.namespace) && aPsa.get(n.namespace) !== n.canEnforce)
      .map((n) => ({ namespace: n.namespace, from: aPsa.get(n.namespace)!, to: n.canEnforce })),
    images: { added: [...bImg].filter((i) => !aImg.has(i)).sort(), removed: [...aImg].filter((i) => !bImg.has(i)).sort() },
    warnings,
  };
}

/** True when `to` has a new finding, or a new risk chain, at or above `severity`. */
export function regressed(d: ReportDiff, severity: Severity): boolean {
  const limit = SEVERITIES.indexOf(severity);
  return d.new.some((f) => SEVERITIES.indexOf(f.severity) <= limit) || d.chains.new.some((c) => SEVERITIES.indexOf(c.severity) <= limit);
}

export function renderDiffMarkdown(d: ReportDiff): string {
  const sign = (n: number) => (n > 0 ? `+${n}` : String(n));
  // Report files are untrusted input (rule 8): every value is escaped or fenced.
  const line = (f: Finding) => `- [${mdSafe(String(f.severity)).toUpperCase()}] ${code(f.id)} — ${mdSafe(f.evidence)}`;
  const out = [
    '# NOIP posture drift',
    '',
    `From ${mdSafe(d.from.scannedAt)} (${mdSafe(d.from.source)}, score ${mdSafe(String(d.from.score))}) to ${mdSafe(d.to.scannedAt)} (${mdSafe(d.to.source)}, score ${mdSafe(String(d.to.score))}): **score ${mdSafe(sign(d.scoreDelta))}**, ` +
      `${d.new.length} new, ${d.resolved.length} resolved, ${d.unchanged} unchanged, ${d.newlySuppressed.length} newly suppressed.`,
    '',
  ];
  if (d.warnings.length) out.push(...d.warnings.map((w) => `> ⚠️ ${mdSafe(w)}`), '');
  out.push('## New findings', '', ...(d.new.length ? d.new.map(line) : ['None.']), '');
  out.push('## Resolved', '', ...(d.resolved.length ? d.resolved.map(line) : ['None.']), '');
  if (d.changed.length) out.push('## Changed evidence', '', ...d.changed.map((c) => `- ${code(c.id)}: ${mdSafe(c.before)} → ${mdSafe(c.after)}`), '');
  if (d.newlySuppressed.length) out.push('## Newly suppressed (accepted risk)', '', ...d.newlySuppressed.map((id) => `- ${code(id)}`), '');
  if (d.controls.length) out.push('## Control status changes', '', ...d.controls.map((c) => `- ${mdSafe(c.id)}: ${mdSafe(c.from)} → ${mdSafe(c.to)}`), '');
  if (d.chains.new.length || d.chains.resolved.length) {
    const c = (x: { id: string; severity: string; title: string }) => `- [${mdSafe(String(x.severity)).toUpperCase()}] ${mdSafe(x.title)} (${code(x.id)})`;
    out.push('## Risk chains', '', ...(d.chains.new.length ? ['New:', '', ...d.chains.new.map(c), ''] : []), ...(d.chains.resolved.length ? ['Resolved:', '', ...d.chains.resolved.map(c), ''] : []));
  }
  if (d.podSecurity.length) {
    out.push('## Pod Security readiness changes', '', ...d.podSecurity.map((p) => `- ${mdSafe(p.namespace)}: could enforce ${mdSafe(p.from)} → ${mdSafe(p.to)}`), '');
  }
  if (d.images.added.length || d.images.removed.length) {
    out.push('## Images', '', `Added: ${d.images.added.map(mdSafe).join(', ') || '—'} · Removed: ${d.images.removed.map(mdSafe).join(', ') || '—'}`, '');
  }
  if (d.checksAdded.length || d.checksRemoved.length) {
    out.push('## Check set changed', '', `Added: ${d.checksAdded.map(mdSafe).join(', ') || '—'} · Removed: ${d.checksRemoved.map(mdSafe).join(', ') || '—'}`, '');
  }
  return out.join('\n');
}
