import { resourceKey } from '../scan.js';
import type { Report } from '../types.js';

const esc = (s: string) => s.replace(/\|/g, '\\|');

/** Human-readable report. Every finding's `Evidence:` line is byte-identical to the JSON `evidence` field. */
export function renderMarkdown(r: Report): string {
  const p = r.provenance;
  const out: string[] = [];
  out.push('# NOIP posture report', '');
  if (r.source === 'demo') {
    out.push('> **DEMO DATA.** This report was generated from the bundled fixture `fixtures/demo-cluster.json`, not a live cluster.', '');
  } else if (r.source === 'manifests') {
    out.push('> **OFFLINE MANIFEST SCAN.** Findings describe the YAML as written, not what is running. Namespace-level checks only see Namespace objects present in the input.', '');
  }
  out.push(
    '| | |',
    '|---|---|',
    `| Source | \`${r.source}\` |`,
    `| Scanned at | ${p.scannedAt} |`,
    `| Cluster | ${esc(p.cluster.context ?? 'n/a')} — Kubernetes ${p.cluster.serverVersion}${p.cluster.platform ? ` (${p.cluster.platform})` : ''}, ${p.cluster.nodeCount} node(s) |`,
    `| Scanner | noip ${p.scanner.version} @ \`${p.scanner.gitSha.slice(0, 12)}\` |`,
    `| Checks run | ${p.checksRun.length} (${p.checksRun.join(', ')}) |`,
    `| Excluded namespaces | ${p.excludedNamespaces.length ? p.excludedNamespaces.join(', ') : 'none'} |`,
    '',
    '## Summary',
    '',
    `Score **${r.summary.score}/100** · ${r.summary.findings} finding(s) · ` +
      `${r.summary.bySeverity.critical} critical, ${r.summary.bySeverity.high} high, ${r.summary.bySeverity.medium} medium, ${r.summary.bySeverity.low} low · ` +
      `${r.summary.checksFailed}/${p.checksRun.length} checks failed · ${r.summary.controlsFailed}/${r.controls.length} controls failed` +
      (r.summary.suppressed ? ` · ${r.summary.suppressed} suppressed (accepted risk, listed below)` : ''),
    '',
  );

  if (r.explanation) {
    out.push('## Explanation (LLM-generated, advisory)', '', r.explanation.summary, '');
    for (const pr of r.explanation.priorities) out.push(`- **${pr.findingId}** — ${pr.why} _Fix:_ ${pr.fix}`);
    if (r.explanation.caveats.length) out.push('', ...r.explanation.caveats.map((c) => `> ${c}`));
    out.push('');
  } else if (r.explanation === null) {
    out.push('_LLM explanation requested but unavailable or rejected by schema validation; deterministic findings below are unaffected._', '');
  }

  out.push('## Findings', '');
  if (!r.findings.length) out.push('No findings.', '');
  for (const f of r.findings) {
    out.push(
      `### [${f.severity.toUpperCase()}] ${f.checkId} — ${f.title}`,
      '',
      `- Resource: \`${resourceKey(f.resource)}\`${f.resource.source ? ` (${f.resource.source.file}${f.resource.source.line ? `:${f.resource.source.line}` : ''})` : ''}`,
      `- Evidence: ${f.evidence}`,
      `- Remediation: ${f.remediation}`,
      `- Controls: ${f.controls.length ? f.controls.join(', ') : '—'}`,
      `- Finding ID: \`${f.id}\``,
      '',
    );
  }

  if (r.suppressed?.length) {
    out.push('## Suppressed (accepted risk)', '', '| Finding | Reason | Owner | Expires |', '|---|---|---|---|');
    for (const x of r.suppressed) out.push(`| \`${x.finding.id}\` | ${esc(x.suppression.reason)} | ${esc(x.suppression.owner)} | ${x.suppression.expires} |`);
    out.push('');
  }
  if (r.warnings?.length) out.push('## Warnings', '', ...r.warnings.map((w) => `- ${w}`), '');

  out.push('## Controls', '', '| Control | Title | Status | Findings | SOC 2 (ref) | HIPAA (ref) |', '|---|---|---|---|---|---|');
  for (const c of r.controls) {
    out.push(
      `| ${c.id} | ${esc(c.title)} | ${c.status === 'fail' ? '❌ fail' : '✅ pass'} | ${c.findingIds.length} | ${c.referenceMappings.soc2.join(', ')} | ${c.referenceMappings.hipaa.join(', ')} |`,
    );
  }
  out.push('', `_${r.mappingDisclaimer}_`, '');

  if (r.network) {
    const n = r.network;
    out.push('## Network (ingested from k8s-netinspect)', '', `CNI: ${n.cni ?? 'unknown'} · tool version: ${n.toolVersion ?? 'unknown'} · input sha256: \`${n.inputSha256}\``, '');
    out.push('| Check | Status | Detail |', '|---|---|---|');
    for (const c of n.checks) out.push(`| ${esc(c.name)} | ${c.status} | ${esc(c.detail ?? '')} |`);
    out.push('', '_NOIP does not diagnose the network itself; this section is reproduced from the input file._', '');
  }
  return out.join('\n');
}
