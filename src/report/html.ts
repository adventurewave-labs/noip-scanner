import { resourceKey } from '../scan.js';
import { SEVERITIES, type Report } from '../types.js';
import { executiveSummary } from './priorities.js';

/**
 * Self-contained, print-ready HTML report for client handoff: no scripts, no external assets, one file.
 * Every value is HTML-escaped; evidence text is identical to the JSON `evidence` field.
 */
const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

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

function execHtml(r: Report): string {
  const ex = executiveSummary(r);
  const list = ex.priorities.length
    ? `<ol>${ex.priorities
        .map(
          (p) =>
            `<li><span class="sev ${p.severity}">${p.severity}</span> <b>${esc(p.checkId)}</b> ${esc(p.title)}: ${p.scope}-scoped, ${p.resources} resource(s)${p.autoFixable ? `, ${p.autoFixable} auto-fixable` : ''}. <span class="muted">e.g. ${p.sample.map((x) => `<code>${esc(x)}</code>`).join(', ')}</span></li>`,
        )
        .join('')}</ol><p class="muted">Quick wins with a deterministic fix: <b>${ex.quickWins}</b> · need a design decision: <b>${ex.needsDesign}</b></p>`
    : '';
  return `<h2>Executive summary</h2><p>${esc(ex.headline)}</p>${list}`;
}

export function renderHtml(r: Report): string {
  const p = r.provenance;
  const tiles: Array<[string, string | number, string?]> = [
    ['Score', `${r.summary.score}/100`],
    ['Findings', r.summary.findings],
    ...SEVERITIES.map((s) => [s, r.summary.bySeverity[s], s] as [string, number, string]),
    ['Controls failed', `${r.summary.controlsFailed}/${r.controls.length}`],
    ...(r.summary.suppressed ? ([['Suppressed', r.summary.suppressed]] as Array<[string, number]>) : []),
  ];
  const banner =
    r.source === 'demo'
      ? '<div class="banner" role="note">DEMO DATA: generated from the bundled fictional fixture, not a live cluster.</div>'
      : r.source === 'manifests'
        ? '<div class="banner" role="note">OFFLINE MANIFEST SCAN: findings describe the YAML as written, not what is running.</div>'
        : '';

  const findings = r.findings.length
    ? `<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Check</th><th>Resource</th><th>Evidence</th><th>Remediation</th><th>Controls</th></tr></thead><tbody>${r.findings
        .map(
          (f) =>
            `<tr id="${esc(f.id)}"><td><span class="sev ${f.severity}">${f.severity}</span></td><td><b>${esc(f.checkId)}</b><br>${esc(f.title)}</td>` +
            `<td><code>${esc(resourceKey(f.resource))}</code>${f.resource.source ? `<br><span class="muted">${esc(f.resource.source.file)}${f.resource.source.line ? `:${f.resource.source.line}` : ''}</span>` : ''}</td>` +
            `<td><code>${esc(f.evidence)}</code></td><td>${esc(f.remediation)}</td><td>${esc(f.controls.join(', ') || '—')}${f.references ? `<br><span class="muted">NSA/CISA: ${esc(f.references.nsaCisa.join('; ') || '—')}<br>NIST 800-190: ${esc(f.references.nist800190.join('; ') || '—')}</span>` : ''}</td></tr>`,
        )
        .join('')}</tbody></table></div>`
    : '<p>No findings.</p>';

  const suppressed = r.suppressed?.length
    ? `<h2>Suppressed (accepted risk)</h2><div class="table-wrap"><table><thead><tr><th>Finding</th><th>Reason</th><th>Owner</th><th>Expires</th></tr></thead><tbody>${r.suppressed
        .map((x) => `<tr><td><code>${esc(x.finding.id)}</code></td><td>${esc(x.suppression.reason)}</td><td>${esc(x.suppression.owner)}</td><td>${esc(x.suppression.expires)}</td></tr>`)
        .join('')}</tbody></table></div>`
    : '';
  const warnings = r.warnings?.length ? `<h2>Warnings</h2><ul>${r.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : '';
  const explanation = r.explanation
    ? `<h2>Explanation <span class="muted">(LLM-generated, advisory)</span></h2><p>${esc(r.explanation.summary)}</p><ol>${r.explanation.priorities
        .map((x) => `<li><a href="#${esc(x.findingId)}"><code>${esc(x.findingId)}</code></a>: ${esc(x.why)} <i>Fix:</i> ${esc(x.fix)}</li>`)
        .join('')}</ol>`
    : '';
  const imported = (r.imported ?? [])
    .map(
      (run) =>
        `<h2>Imported: ${esc(run.tool)}${run.version ? ` ${esc(run.version)}` : ''} <span class="muted">(not in NOIP's score)</span></h2>` +
        (run.results.length
          ? `<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>${run.results
              .map((x) => `<tr><td><span class="sev ${x.severity}">${x.severity}</span></td><td><code>${esc(x.ruleId)}</code></td><td>${x.location ? `<code>${esc(x.location.uri)}${x.location.line ? `:${x.location.line}` : ''}</code>` : '—'}</td><td>${esc(x.message)}</td></tr>`)
              .join('')}</tbody></table></div>`
          : '<p>No results.</p>'),
    )
    .join('');
  const network = r.network
    ? `<h2>Network <span class="muted">(ingested from k8s-netinspect)</span></h2><div class="table-wrap"><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>${r.network.checks
        .map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.status)}</td><td>${esc(c.detail ?? '')}</td></tr>`)
        .join('')}</tbody></table></div>`
    : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="noip ${esc(p.scanner.version)}">
<title>NOIP posture report: ${esc(p.cluster.context ?? r.source)}</title><style>${CSS}</style></head>
<body><main>
<h1>Kubernetes posture report</h1>
<p class="muted">${esc(p.cluster.context ?? 'n/a')} · Kubernetes ${esc(p.cluster.serverVersion)} · scanned ${esc(p.scannedAt)} · source <b>${esc(r.source)}</b></p>
${banner}
<div class="tiles">${tiles.map(([k, v, cls]) => `<div class="tile"><span>${esc(k)}</span><b${cls ? ` class="${cls}"` : ''}>${esc(v)}</b></div>`).join('')}</div>
${execHtml(r)}
${explanation}
<h2>Findings</h2>${findings}
${suppressed}${warnings}
<h2>Controls</h2><div class="table-wrap"><table><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Findings</th><th>SOC 2 (ref)</th><th>HIPAA (ref)</th></tr></thead><tbody>${r.controls
    .map(
      (c) =>
        `<tr><td>${esc(c.id)}</td><td>${esc(c.title)}</td><td class="${c.status}">${c.status}</td><td>${c.findingIds.length}</td><td>${esc(c.referenceMappings.soc2.join(', '))}</td><td>${esc(c.referenceMappings.hipaa.join(', '))}</td></tr>`,
    )
    .join('')}</tbody></table></div>
<p class="muted"><i>${esc(r.mappingDisclaimer)}</i></p>
${imported}${network}
<h2>Provenance</h2><dl>
<dt>Scanner</dt><dd>noip ${esc(p.scanner.version)} @ <code>${esc(p.scanner.gitSha)}</code></dd>
<dt>Cluster</dt><dd>${esc(p.cluster.context ?? 'n/a')}, Kubernetes ${esc(p.cluster.serverVersion)}${p.cluster.platform ? ` (${esc(p.cluster.platform)})` : ''}, ${p.cluster.nodeCount} node(s)</dd>
<dt>Scanned at</dt><dd>${esc(p.scannedAt)}</dd>
<dt>Checks run</dt><dd>${esc(p.checksRun.join(', '))}</dd>
<dt>Excluded namespaces</dt><dd>${esc(p.excludedNamespaces.join(', ') || 'none')}</dd>
${p.minSeverity ? `<dt>Minimum severity</dt><dd>${esc(p.minSeverity)}</dd>` : ''}
</dl>
</main></body></html>
`;
}
