import { resourceKey } from '../scan.js';
import { SEVERITIES, type Report } from '../types.js';
import { localise, STRINGS, type Lang, type Strings } from './i18n.js';
import { executiveSummary } from './priorities.js';

/**
 * Self-contained, print-ready HTML report for client handoff: no scripts, no external assets, one file.
 * Every value is HTML-escaped; evidence text is identical to the JSON `evidence` field.
 */
const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
/** Minimal inline markdown in our own strings: **bold** only. Applied after escaping. */
const bold = (s: string) => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
/** Our own strings may quote paths in `backticks`; show them as code. Applied after escaping. */
const ticks = (s: string) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');

const CSS = `
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5b5b5b;--line:#e3e3e3;--card:#f7f7f8;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b5563;--ok:#15803d;--warn-bg:#fef3c7;--warn-fg:#78350f}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--fg:#ececec;--muted:#a3a3a3;--line:#2e2e2e;--card:#1c1c1e;--crit:#f2b8b5;--high:#fdba74;--med:#fcd34d;--low:#cbd5e1;--ok:#86efac;--warn-bg:#3b2f0b;--warn-fg:#fde68a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}.banner{background:var(--warn-bg);color:var(--warn-fg);padding:10px 14px;border-radius:8px;font-weight:600;margin:12px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.tile b{display:block;font-size:22px}.tile span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
.sev{display:inline-block;min-width:66px;text-align:center;font-weight:700;font-size:11px;padding:2px 6px;border-radius:999px;border:1px solid currentColor;text-transform:uppercase}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.pass{color:var(--ok);font-weight:600}.fail{color:var(--crit);font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}
.table-wrap{overflow-x:auto}
@media print{body{background:#fff;color:#000}main{max-width:none;padding:0}.tile,.banner{border:1px solid #999}h2{break-after:avoid}tr{break-inside:avoid}}
`;

function execHtml(r: Report, t: Strings): string {
  const L = localise(t);
  const ex = executiveSummary(r);
  const headline = r.findings.length
    ? t.headline(r.summary.score, r.findings.length, r.summary.bySeverity.critical, r.summary.bySeverity.high, ex.failedChecks, r.provenance.checksRun.length, ex.quickWins)
    : t.headlineClean(r.provenance.checksRun.length, r.summary.score);
  const list = ex.priorities.length
    ? `<p class="muted">${esc(t.fixFirst)}</p><ol>${ex.priorities
        .map(
          (p) =>
            `<li><span class="sev ${p.severity}">${esc(t.sev[p.severity])}</span> <b>${esc(p.checkId)}</b> ${esc(L.title(p.checkId, p.title))}: ${esc(t.priorityLine(p.severity, p.scope, p.resources, p.autoFixable))}. <span class="muted">${esc(t.eg)} ${p.sample.map((x) => `<code>${esc(x)}</code>`).join(', ')}</span></li>`,
        )
        .join('')}</ol><p class="muted">${t.quickWins(ex.quickWins, ex.needsDesign).map(bold).join(' · ')}</p>`
    : '';
  return `<h2>${esc(t.executive)}</h2><p>${esc(headline)}</p>${list}`;
}

export function renderHtml(r: Report, lang: Lang = 'en'): string {
  const t = STRINGS[lang];
  const L = localise(t);
  const p = r.provenance;
  const tiles: Array<[string, string | number, string?]> = [
    [t.score, `${r.summary.score}/100`],
    [t.findings, r.summary.findings],
    ...SEVERITIES.map((s) => [t.sev[s], r.summary.bySeverity[s], s] as [string, number, string]),
    [t.controlsFailedTile, `${r.summary.controlsFailed}/${r.controls.length}`],
    ...(r.summary.suppressed ? ([[t.suppressedTitle, r.summary.suppressed]] as Array<[string, number]>) : []),
  ];
  const banner =
    r.source === 'demo'
      ? `<div class="banner" role="note">${ticks(t.demoBanner)}</div>`
      : r.source === 'manifests'
        ? `<div class="banner" role="note">${ticks(t.manifestsBanner)}</div>`
        : '';

  const findings = r.findings.length
    ? `<div class="table-wrap"><table><thead><tr><th>${esc(t.importedCols[0])}</th><th>${esc(t.check)}</th><th>${esc(t.resource)}</th><th>${esc(t.evidence)}</th><th>${esc(t.remediation)}</th><th>${esc(t.controls)}</th></tr></thead><tbody>${r.findings
        .map(
          (f) =>
            `<tr id="${esc(f.id)}"><td><span class="sev ${f.severity}">${esc(t.sev[f.severity])}</span></td><td><b>${esc(f.checkId)}</b><br>${esc(L.title(f.checkId, f.title))}</td>` +
            `<td><code>${esc(resourceKey(f.resource))}</code>${f.resource.source ? `<br><span class="muted">${esc(f.resource.source.file)}${f.resource.source.line ? `:${f.resource.source.line}` : ''}</span>` : ''}</td>` +
            `<td><code>${esc(f.evidence)}</code></td><td>${esc(L.remediation(f.checkId, f.remediation))}</td><td>${esc(f.controls.join(', ') || '—')}${f.references ? `<br><span class="muted">NSA/CISA: ${esc(f.references.nsaCisa.join('; ') || '—')}<br>NIST 800-190: ${esc(f.references.nist800190.join('; ') || '—')}</span>` : ''}</td></tr>`,
        )
        .join('')}</tbody></table></div>`
    : `<p>${esc(t.noFindings)}</p>`;

  const suppressed = r.suppressed?.length
    ? `<h2>${esc(t.suppressedTitle)}</h2><div class="table-wrap"><table><thead><tr>${t.suppressedCols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.suppressed
        .map((x) => `<tr><td><code>${esc(x.finding.id)}</code></td><td>${esc(x.suppression.reason)}</td><td>${esc(x.suppression.owner)}</td><td>${esc(x.suppression.expires)}</td></tr>`)
        .join('')}</tbody></table></div>`
    : '';
  const warnings = r.warnings?.length ? `<h2>${esc(t.warnings)}</h2><ul>${r.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : '';
  const [explTitle, explNote] = t.explanation.split(' (');
  const explanation = r.explanation
    ? `<h2>${esc(explTitle)} <span class="muted">(${esc(explNote)}</span></h2><p>${esc(r.explanation.summary)}</p><ol>${r.explanation.priorities
        .map((x) => `<li><a href="#${esc(x.findingId)}"><code>${esc(x.findingId)}</code></a>: ${esc(x.why)} <i>${esc(t.fix)}</i> ${esc(x.fix)}</li>`)
        .join('')}</ol>`
    : '';
  const imported = (r.imported ?? [])
    .map(
      (run) =>
        `<h2>${esc(t.imported)}: ${esc(run.tool)}${run.version ? ` ${esc(run.version)}` : ''} <span class="muted">(${esc(t.notInScore)})</span></h2>` +
        (run.results.length
          ? `<div class="table-wrap"><table><thead><tr>${t.importedCols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${run.results
              .map((x) => `<tr><td><span class="sev ${x.severity}">${esc(t.sev[x.severity])}</span></td><td><code>${esc(x.ruleId)}</code></td><td>${x.location ? `<code>${esc(x.location.uri)}${x.location.line ? `:${x.location.line}` : ''}</code>` : '—'}</td><td>${esc(x.message)}</td></tr>`)
              .join('')}</tbody></table></div>`
          : `<p>${esc(t.noResults)}</p>`),
    )
    .join('');
  const [netTitle, netNote] = t.network.split(' (');
  const psa = r.podSecurity?.namespaces.length
    ? `<h2>${esc(t.psa)}</h2><p class="muted">${esc(t.psaNote(r.podSecurity.policyVersion))}</p><div class="table-wrap"><table><thead><tr>${t.psaCols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.podSecurity.namespaces
        .map(
          (n) =>
            `<tr><td><code>${esc(n.namespace)}</code></td><td>${n.enforce ? `<code>${esc(n.enforce)}</code>` : esc(t.psaUnset)}</td><td><b>${esc(n.canEnforce)}</b></td><td>${esc(n.pods)}</td><td>${
              n.blockers.map((b) => `<code>${esc(b.resource)}</code>: ${esc(b.reasons.join('; '))}`).join('<br>') || '—'
            }</td></tr>`,
        )
        .join('')}</tbody></table></div>`
    : '';
  const network = r.network
    ? `<h2>${esc(netTitle)} <span class="muted">(${esc(netNote)}</span></h2><p class="muted">CNI: ${esc(r.network.cni ?? t.unknown)} · ${esc(t.networkMeta[0])}: ${esc(r.network.toolVersion ?? t.unknown)} · ${esc(t.networkMeta[1])}: <code>${esc(r.network.inputSha256)}</code></p><div class="table-wrap"><table><thead><tr>${t.networkCols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.network.checks
        .map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.status)}</td><td>${esc(c.detail ?? '')}</td></tr>`)
        .join('')}</tbody></table></div>`
    : '';

  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="noip ${esc(p.scanner.version)}">
<title>${esc(t.title)}: ${esc(p.cluster.context ?? r.source)}</title><style>${CSS}</style></head>
<body><main>
<h1>${esc(t.htmlTitle)}</h1>
<p class="muted">${esc(p.cluster.context ?? 'n/a')} · Kubernetes ${esc(p.cluster.serverVersion)} · ${esc(t.scannedAt.toLowerCase())} ${esc(p.scannedAt)} · ${esc(t.source.toLowerCase())} <b>${esc(r.source)}</b></p>
${banner}
<div class="tiles">${tiles.map(([k, v, cls]) => `<div class="tile"><span>${esc(k)}</span><b${cls ? ` class="${cls}"` : ''}>${esc(v)}</b></div>`).join('')}</div>
${p.cluster.versionSupport && t.support(p.cluster.versionSupport) ? `<div class="banner" role="note">${esc(t.support(p.cluster.versionSupport))}</div>` : ''}
${execHtml(r, t)}
${explanation}
<h2>${esc(t.findings)}</h2>${findings}
${suppressed}${warnings}
<h2>${esc(t.controls)}</h2><div class="table-wrap"><table><thead><tr>${t.controlsCols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${r.controls
    .map(
      (c) =>
        `<tr><td>${esc(c.id)}</td><td>${esc(L.control(c.id, c.title))}</td><td class="${c.status}">${esc(c.status === 'fail' ? t.fail : t.pass)}</td><td>${c.findingIds.length}</td><td>${esc(c.referenceMappings.soc2.join(', '))}</td><td>${esc(c.referenceMappings.hipaa.join(', '))}</td></tr>`,
    )
    .join('')}</tbody></table></div>
<p class="muted"><i>${esc(L.disclaimer(r.mappingDisclaimer))}</i></p>
${psa}${imported}${network}
<h2>${esc(t.provenance)}</h2><dl>
<dt>${esc(t.scanner)}</dt><dd>noip ${esc(p.scanner.version)} @ <code>${esc(p.scanner.gitSha)}</code></dd>
<dt>${esc(t.cluster)}</dt><dd>${esc(p.cluster.context ?? 'n/a')}, Kubernetes ${esc(p.cluster.serverVersion)}${p.cluster.platform ? ` (${esc(p.cluster.platform)})` : ''}, ${esc(t.nodes(p.cluster.nodeCount))}</dd>
<dt>${esc(t.scannedAt)}</dt><dd>${esc(p.scannedAt)}</dd>
<dt>${esc(t.checksRun)}</dt><dd>${esc(p.checksRun.join(', '))}</dd>
<dt>${esc(t.excluded)}</dt><dd>${esc(p.excludedNamespaces.join(', ') || t.none)}</dd>
${p.minSeverity ? `<dt>${esc(t.minSeverity)}</dt><dd>${esc(p.minSeverity)}</dd>` : ''}
</dl>
</main></body></html>
`;
}
