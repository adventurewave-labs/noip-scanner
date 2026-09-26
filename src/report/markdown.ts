import { resourceKey } from '../scan.js';
import { executiveSummary } from './priorities.js';
import type { Report } from '../types.js';
import { localise, STRINGS, type Lang } from './i18n.js';

/**
 * Neutralise untrusted text (imported SARIF, manifest names) for Markdown: one line, no raw HTML,
 * no link syntax, no table breaks. Renders visually identical to the source text.
 */
export const mdSafe = (s: string) =>
  s.replace(/\s+/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\]\(/g, ']\\(').replace(/\|/g, '\\|');
const esc = mdSafe;
/** Inline code that can't be broken out of: fence longer than any backtick run inside. */
const code = (s: string) => {
  const t = s.replace(/\s+/g, ' ');
  const run = Math.max(0, ...(t.match(/`+/g) ?? []).map((m) => m.length));
  const fence = '`'.repeat(run + 1);
  return run ? `${fence} ${t} ${fence}` : `${fence}${t}${fence}`;
};

/** Human-readable report. Evidence is the JSON `evidence` text, escaped for Markdown (renders identically). */
export function renderMarkdown(r: Report, lang: Lang = 'en'): string {
  const t = STRINGS[lang];
  const L = localise(t);
  const p = r.provenance;
  const out: string[] = [];
  out.push(`# ${t.title}`, '');
  if (r.source === 'demo') {
    const [head, ...rest] = t.demoBanner.split('. ');
    out.push(`> **${head}.** ${rest.join('. ')}`, '');
  } else if (r.source === 'manifests') {
    const [head, ...rest] = t.manifestsBanner.split('. ');
    out.push(`> **${head}.** ${rest.join('. ')}`, '');
  }
  out.push(
    '| | |',
    '|---|---|',
    `| ${t.source} | \`${r.source}\` |`,
    `| ${t.scannedAt} | ${p.scannedAt} |`,
    `| ${t.cluster} | ${esc(p.cluster.context ?? 'n/a')} — Kubernetes ${p.cluster.serverVersion}${p.cluster.platform ? ` (${p.cluster.platform})` : ''}, ${t.nodes(p.cluster.nodeCount)} |`,
    `| ${t.scanner} | noip ${p.scanner.version} @ \`${p.scanner.gitSha.slice(0, 12)}\` |`,
    `| ${t.checksRun} | ${p.checksRun.length} (${p.checksRun.join(', ')}) |`,
    `| ${t.excluded} | ${p.excludedNamespaces.length ? p.excludedNamespaces.join(', ') : t.none} |`,
    '',
    `## ${t.summary}`,
    '',
    `${t.score} **${r.summary.score}/100** · ${t.findingsN(r.summary.findings)} · ` +
      `${r.summary.bySeverity.critical} ${t.sev.critical}, ${r.summary.bySeverity.high} ${t.sev.high}, ${r.summary.bySeverity.medium} ${t.sev.medium}, ${r.summary.bySeverity.low} ${t.sev.low} · ` +
      `${t.checksFailed(r.summary.checksFailed, p.checksRun.length)} · ${t.controlsFailed(r.summary.controlsFailed, r.controls.length)}` +
      (r.summary.suppressed ? ` · ${t.suppressedN(r.summary.suppressed)}` : ''),
    '',
  );

  const ex = executiveSummary(r);
  const headline = r.findings.length
    ? t.headline(r.summary.score, r.findings.length, r.summary.bySeverity.critical, r.summary.bySeverity.high, ex.failedChecks, p.checksRun.length, ex.quickWins)
    : t.headlineClean(p.checksRun.length, r.summary.score);
  out.push(`## ${t.executive}`, '', headline, '');
  if (ex.priorities.length) {
    out.push(t.fixFirst, '');
    ex.priorities.forEach((pr, i) =>
      out.push(
        `${i + 1}. **${pr.checkId}: ${esc(L.title(pr.checkId, pr.title))}**: ${t.priorityLine(pr.severity, pr.scope, pr.resources, pr.autoFixable)} (${t.eg} ${pr.sample.map(code).join(', ')})`,
      ),
    );
    out.push('', t.quickWins(ex.quickWins, ex.needsDesign).join(' · '), '');
  }

  if (r.explanation) {
    out.push(`## ${t.explanation}`, '', esc(r.explanation.summary), '');
    for (const pr of r.explanation.priorities) out.push(`- **${esc(pr.findingId)}** — ${esc(pr.why)} _${t.fix}_ ${esc(pr.fix)}`);
    if (r.explanation.caveats.length) out.push('', ...r.explanation.caveats.map((c) => `> ${esc(c)}`));
    out.push('');
  } else if (r.explanation === null) {
    out.push(`_${t.explanationMissing}_`, '');
  }

  out.push(`## ${t.findings}`, '');
  if (!r.findings.length) out.push(t.noFindings, '');
  for (const f of r.findings) {
    out.push(
      `### [${t.sev[f.severity].toUpperCase()}] ${f.checkId} — ${L.title(f.checkId, f.title)}`,
      '',
      `- ${t.resource}: ${code(resourceKey(f.resource))}${f.resource.source ? ` (${esc(f.resource.source.file)}${f.resource.source.line ? `:${f.resource.source.line}` : ''})` : ''}`,
      `- ${t.evidence}: ${esc(f.evidence)}`,
      `- ${t.remediation}: ${L.remediation(f.checkId, f.remediation)}`,
      `- ${t.controls}: ${f.controls.length ? f.controls.join(', ') : '—'}`,
      ...(f.references ? [`- ${t.references}: NSA/CISA ${f.references.nsaCisa.join('; ') || '—'} · NIST SP 800-190 ${f.references.nist800190.join('; ') || '—'}`] : []),
      `- ${t.findingId}: ${code(f.id)}`,
      '',
    );
  }

  if (r.suppressed?.length) {
    out.push(`## ${t.suppressedTitle}`, '', `| ${t.suppressedCols.join(' | ')} |`, '|---|---|---|---|');
    for (const x of r.suppressed) out.push(`| ${code(x.finding.id)} | ${esc(x.suppression.reason)} | ${esc(x.suppression.owner)} | ${x.suppression.expires} |`);
    out.push('');
  }
  if (r.warnings?.length) out.push(`## ${t.warnings}`, '', ...r.warnings.map((w) => `- ${esc(w)}`), '');

  out.push(`## ${t.controls}`, '', `| ${t.controlsCols.join(' | ')} |`, '|---|---|---|---|---|---|');
  for (const c of r.controls) {
    out.push(
      `| ${c.id} | ${esc(L.control(c.id, c.title))} | ${c.status === 'fail' ? `❌ ${t.fail}` : `✅ ${t.pass}`} | ${c.findingIds.length} | ${c.referenceMappings.soc2.join(', ')} | ${c.referenceMappings.hipaa.join(', ')} |`,
    );
  }
  out.push('', `_${L.disclaimer(r.mappingDisclaimer)}_`, '');

  for (const run of r.imported ?? []) {
    out.push(`## ${t.imported}: ${esc(run.tool)}${run.version ? ` ${esc(run.version)}` : ''}`, '', t.importedFrom(code(run.inputFile), run.inputSha256.slice(0, 12)), '');
    if (!run.results.length) out.push(t.noResults, '');
    else {
      out.push(`| ${t.importedCols.join(' | ')} |`, '|---|---|---|---|');
      for (const x of run.results) out.push(`| ${t.sev[x.severity]} | ${esc(x.ruleId)} | ${x.location ? esc(`${x.location.uri}${x.location.line ? `:${x.location.line}` : ''}`) : '—'} | ${esc(x.message)} |`);
      out.push('');
    }
  }

  if (r.network) {
    const n = r.network;
    out.push(`## ${t.network}`, '', `CNI: ${n.cni ?? t.unknown} · tool version: ${n.toolVersion ?? t.unknown} · input sha256: \`${n.inputSha256}\``, '');
    out.push(`| ${t.networkCols.join(' | ')} |`, '|---|---|---|');
    for (const c of n.checks) out.push(`| ${esc(c.name)} | ${c.status} | ${esc(c.detail ?? '')} |`);
    out.push('', `_${t.networkNote}_`, '');
  }
  return out.join('\n');
}
