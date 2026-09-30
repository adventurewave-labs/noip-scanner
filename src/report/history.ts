import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { SEVERITIES, type DataSource, type Report, type Severity } from '../types.js';
import type { Lang } from './i18n.js';
import { mdSafe } from './markdown.js';

/**
 * Posture history: the score trend across saved JSON reports, one series per scan target
 * (source + kubeconfig context). Pure over its inputs; `loadHistory` is the only I/O.
 *
 * Scores are only comparable when the same checks ran with the same severity filter, so a point
 * whose check set or `minSeverity` differs from the previous point is flagged, and its delta is
 * left out instead of being presented as drift.
 */
export interface HistoryPoint {
  file: string;
  scannedAt: string;
  score: number;
  findings: number;
  bySeverity: Record<Severity, number>;
  controlsFailed: number;
  suppressed: number;
  scannerVersion: string;
  gitSha: string;
  /** Score change from the previous comparable point; null for the first point or after a scope change. */
  delta: number | null;
  /** Set when the check set or severity filter differs from the previous point. */
  scopeChanged?: ScopeChange[];
}

export type ScopeChange = 'checks' | 'minSeverity' | 'namespaces';

export interface HistoryTarget {
  key: string;
  source: DataSource;
  context?: string;
  points: HistoryPoint[];
}

export interface History {
  targets: HistoryTarget[];
  skipped: Array<{ file: string; reason: string }>;
}

export function isReport(x: unknown): x is Report {
  const r = x as Report;
  return Boolean(r) && typeof r === 'object' && r.schemaVersion === '1' && Array.isArray(r.findings) && Number.isFinite(r.summary?.score) && typeof r.provenance?.scannedAt === 'string';
}

/** Report files are untrusted input: only strict UTC ISO-8601 timestamps are accepted (no locale parsing, no free text). */
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
/** Coerce a count from an untrusted file to a non-negative integer, so nothing but digits reaches a renderer. */
const count = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const text = (v: unknown): string => (typeof v === 'string' ? v : 'unknown');

/** Pure: group reports into per-target series sorted by scan time. */
export function buildHistory(entries: Array<{ file: string; report: unknown }>): History {
  const skipped: History['skipped'] = [];
  const groups = new Map<string, { target: HistoryTarget; reports: Array<{ file: string; r: Report }> }>();
  for (const { file, report } of entries) {
    if (!isReport(report)) {
      skipped.push({ file, reason: 'not a NOIP report (schemaVersion 1)' });
      continue;
    }
    if (!ISO_UTC.test(report.provenance.scannedAt) || Number.isNaN(Date.parse(report.provenance.scannedAt))) {
      skipped.push({ file, reason: 'invalid scannedAt' });
      continue;
    }
    const context = report.provenance.cluster?.context;
    const key = `${report.source}:${context ?? 'default'}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { target: { key, source: report.source, ...(context ? { context } : {}), points: [] }, reports: [] }));
    g.reports.push({ file, r: report });
  }

  const targets = [...groups.values()].map(({ target, reports }) => {
    reports.sort((a, b) => Date.parse(a.r.provenance.scannedAt) - Date.parse(b.r.provenance.scannedAt) || a.file.localeCompare(b.file));
    let prev: Report | undefined;
    for (const { file, r } of reports) {
      if (prev && prev.provenance.scannedAt === r.provenance.scannedAt && prev.summary.score === r.summary.score && prev.findings.length === r.findings.length) {
        skipped.push({ file, reason: 'duplicate of an earlier report (same target and scan time)' });
        continue;
      }
      const scope = prev ? scopeChange(prev, r) : undefined;
      target.points.push({
        file,
        scannedAt: r.provenance.scannedAt,
        score: Math.round(r.summary.score),
        findings: count(r.summary.findings),
        bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, count(r.summary.bySeverity?.[s])])) as Record<Severity, number>,
        controlsFailed: count(r.summary.controlsFailed),
        suppressed: count(r.summary.suppressed),
        scannerVersion: text(r.provenance.scanner?.version),
        gitSha: text(r.provenance.scanner?.gitSha),
        delta: prev && !scope ? r.summary.score - prev.summary.score : null,
        ...(scope ? { scopeChanged: scope } : {}),
      });
      prev = r;
    }
    return target;
  });
  targets.sort((a, b) => a.key.localeCompare(b.key));
  return { targets, skipped };
}

function scopeChange(a: Report, b: Report): ScopeChange[] | undefined {
  const reasons: ScopeChange[] = [];
  const ca = [...(a.provenance.checksRun ?? [])].sort().join(',');
  const cb = [...(b.provenance.checksRun ?? [])].sort().join(',');
  if (ca !== cb) reasons.push('checks');
  if ((a.provenance.minSeverity ?? 'low') !== (b.provenance.minSeverity ?? 'low')) reasons.push('minSeverity');
  const na = [...(a.provenance.excludedNamespaces ?? [])].sort().join(',');
  const nb = [...(b.provenance.excludedNamespaces ?? [])].sort().join(',');
  if (na !== nb) reasons.push('namespaces');
  return reasons.length ? reasons : undefined;
}

/** Read report files and directories (recursively, `*.json`). Unreadable or non-report JSON is skipped, not fatal. */
export function loadHistory(paths: string[]): History {
  const entries: Array<{ file: string; report: unknown }> = [];
  const skipped: History['skipped'] = [];
  const visit = (p: string, top: boolean) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const name of readdirSync(p).sort()) visit(join(p, name), false);
      return;
    }
    if (!top && !p.endsWith('.json')) return;
    try {
      entries.push({ file: p, report: JSON.parse(readFileSync(p, 'utf8')) });
    } catch {
      skipped.push({ file: p, reason: 'not valid JSON' });
    }
  };
  for (const p of paths) visit(p, true);
  const h = buildHistory(entries);
  return { targets: h.targets, skipped: [...skipped, ...h.skipped] };
}

// ---------- rendering ----------

interface HStrings {
  title: string;
  empty: string;
  target: (source: string, context: string) => string;
  trend: (n: number, from: string, to: string, first: number, last: number, best: number, worst: number) => string;
  single: (at: string, score: number) => string;
  cols: [string, string, string, string, string, string, string];
  scope: string;
  why: Record<ScopeChange, string>;
  skipped: string;
  chartLabel: (target: string) => string;
  point: (at: string, score: number, findings: number) => string;
  dataTable: string;
  defaultContext: string;
}

const H: Record<Lang, HStrings> = {
  en: {
    title: 'NOIP posture history',
    empty: 'No NOIP reports found.',
    target: (s, c) => `Target: ${s} · context ${c}`,
    trend: (n, from, to, first, last, best, worst) =>
      `${n} scan(s) from ${from} to ${to}. Score ${first} → ${last} (${signed(last - first)}); best ${best}, worst ${worst}.`,
    single: (at, sc) => `1 scan on ${at}, score ${sc}. Save more reports to see a trend.`,
    cols: ['Scanned at', 'Score', 'Δ', 'Findings', 'Critical / High / Medium / Low', 'Controls failed', 'Scanner'],
    scope: 'not comparable',
    why: { checks: 'check set changed', minSeverity: 'severity filter changed', namespaces: 'namespace scope changed' },
    skipped: 'Skipped files',
    chartLabel: (t) => `Posture score over time for ${t} (0–100)`,
    point: (at, s, f) => `${at}: score ${s}, ${f} finding(s)`,
    dataTable: 'Data',
    defaultContext: 'default',
  },
  es: {
    title: 'Historial de postura NOIP',
    empty: 'No se encontraron informes NOIP.',
    target: (s, c) => `Objetivo: ${s} · contexto ${c}`,
    trend: (n, from, to, first, last, best, worst) =>
      `${n} escaneo(s) del ${from} al ${to}. Puntuación ${first} → ${last} (${signed(last - first)}); mejor ${best}, peor ${worst}.`,
    single: (at, sc) => `1 escaneo el ${at}, puntuación ${sc}. Guarde más informes para ver una tendencia.`,
    cols: ['Escaneado', 'Puntuación', 'Δ', 'Hallazgos', 'Crítico / Alto / Medio / Bajo', 'Controles fallidos', 'Escáner'],
    scope: 'no comparable',
    why: { checks: 'cambió el conjunto de comprobaciones', minSeverity: 'cambió el filtro de severidad', namespaces: 'cambió el alcance de namespaces' },
    skipped: 'Archivos omitidos',
    chartLabel: (t) => `Puntuación de postura a lo largo del tiempo para ${t} (0–100)`,
    point: (at, s, f) => `${at}: puntuación ${s}, ${f} hallazgo(s)`,
    dataTable: 'Datos',
    defaultContext: 'predeterminado',
  },
};

const signed = (n: number) => (n > 0 ? `+${n}` : String(n));
const day = (iso: string) => iso.slice(0, 10);
const stamp = (iso: string) => iso.replace('T', ' ').replace(/\.\d+Z$|Z$/, ' UTC');

function trendLine(t: HistoryTarget, s: HStrings): string {
  const scores = t.points.map((p) => p.score);
  const first = t.points[0]!;
  const last = t.points[t.points.length - 1]!;
  if (t.points.length === 1) return s.single(day(first.scannedAt), first.score);
  return s.trend(t.points.length, day(first.scannedAt), day(last.scannedAt), first.score, last.score, Math.max(...scores), Math.min(...scores));
}

const deltaCell = (p: HistoryPoint, s: HStrings) => (p.scopeChanged ? `${s.scope}: ${p.scopeChanged.map((c) => s.why[c]).join('; ')}` : p.delta === null ? '—' : signed(p.delta));
const sevCell = (p: HistoryPoint) => SEVERITIES.map((x) => p.bySeverity[x]).join(' / ');

export function renderHistoryMarkdown(h: History, lang: Lang = 'en'): string {
  const s = H[lang];
  const out = [`# ${s.title}`, ''];
  if (!h.targets.length) out.push(s.empty, '');
  for (const t of h.targets) {
    out.push(`## ${mdSafe(s.target(t.source, t.context ?? s.defaultContext))}`, '', trendLine(t, s), '');
    out.push(`| ${s.cols.join(' | ')} |`, `|${s.cols.map(() => '---').join('|')}|`);
    for (const p of t.points) {
      out.push(`| ${mdSafe(stamp(p.scannedAt))} | ${p.score} | ${deltaCell(p, s)} | ${p.findings} | ${sevCell(p)} | ${p.controlsFailed} | ${mdSafe(`${p.scannerVersion} (${p.gitSha.slice(0, 7)})`)} |`);
    }
    out.push('');
  }
  if (h.skipped.length) out.push(`## ${s.skipped}`, '', ...h.skipped.map((k) => `- ${mdSafe(k.file)}: ${k.reason}`), '');
  return out.join('\n');
}

const esc = (v: unknown) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/* Chart chrome and series-1 from the validated reference palette (light and dark steps). */
const CSS = `
.viz-root{color-scheme:light;--surface-1:#fcfcfb;--page:#f9f9f7;--text-primary:#0b0b0b;--text-secondary:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--series-1:#2a78d6;--border:rgba(11,11,11,.10)}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#0d0d0d;--text-primary:#fff;--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--series-1:#3987e5;--border:rgba(255,255,255,.10)}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#0d0d0d;--text-primary:#fff;--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--series-1:#3987e5;--border:rgba(255,255,255,.10)}
*{box-sizing:border-box}body.viz-root{margin:0;background:var(--page);color:var(--text-primary);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 16px}h2{font-size:17px;margin:0 0 4px}
section{background:var(--surface-1);border:1px solid var(--border);border-radius:12px;padding:16px;margin:0 0 20px}
.muted{color:var(--text-secondary)}svg{display:block;width:100%;min-width:520px;height:auto}.chart-wrap{overflow-x:auto;margin:12px 0}
.grid{stroke:var(--grid);stroke-width:1}.axis{stroke:var(--axis);stroke-width:1}.tick{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.line{fill:none;stroke:var(--series-1);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.dot{fill:var(--series-1);stroke:var(--surface-1);stroke-width:2}.hit{fill:transparent}.hit:hover+.dot,.hit:focus+.dot{r:6}
.val{fill:var(--text-primary);font-size:12px;font-weight:600}
details{margin-top:4px}summary{cursor:pointer;color:var(--text-secondary)}
table{width:100%;border-collapse:collapse;font-size:13px;font-variant-numeric:tabular-nums;margin-top:8px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);white-space:nowrap}th{color:var(--text-secondary);font-weight:600}
.table-wrap{overflow-x:auto}
@media print{body.viz-root{background:#fff}section{break-inside:avoid}}
`;

const W = 640;
const HGT = 220;
const PAD = { l: 36, r: 40, t: 14, b: 28 };

function chart(t: HistoryTarget, s: HStrings, label: string): string {
  const pts = t.points;
  const times = pts.map((p) => Date.parse(p.scannedAt));
  const t0 = Math.min(...times);
  const span = Math.max(...times) - t0;
  const x = (i: number) => PAD.l + (pts.length === 1 ? (W - PAD.l - PAD.r) / 2 : span > 0 ? ((times[i]! - t0) / span) * (W - PAD.l - PAD.r) : (i / (pts.length - 1)) * (W - PAD.l - PAD.r));
  const y = (score: number) => PAD.t + (1 - Math.max(0, Math.min(100, score)) / 100) * (HGT - PAD.t - PAD.b);
  const grid = [0, 25, 50, 75, 100]
    .map((v) => `<line class="${v === 0 ? 'axis' : 'grid'}" x1="${PAD.l}" x2="${W - PAD.r}" y1="${y(v)}" y2="${y(v)}"/><text class="tick" x="${PAD.l - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`)
    .join('');
  const xTicks =
    pts.length === 1
      ? `<text class="tick" x="${x(0)}" y="${HGT - 8}" text-anchor="middle">${esc(day(pts[0]!.scannedAt))}</text>`
      : `<text class="tick" x="${x(0)}" y="${HGT - 8}" text-anchor="start">${esc(day(pts[0]!.scannedAt))}</text><text class="tick" x="${x(pts.length - 1)}" y="${HGT - 8}" text-anchor="end">${esc(day(pts[pts.length - 1]!.scannedAt))}</text>`;
  const path = pts.length > 1 ? `<path class="line" d="${pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join('')}"/>` : '';
  const dots = pts
    .map(
      (p, i) =>
        `<g><title>${esc(s.point(stamp(p.scannedAt), p.score, p.findings))}</title><circle class="hit" cx="${x(i).toFixed(1)}" cy="${y(p.score).toFixed(1)}" r="12" tabindex="0"/><circle class="dot" cx="${x(i).toFixed(1)}" cy="${y(p.score).toFixed(1)}" r="4"/></g>`,
    )
    .join('');
  const last = pts[pts.length - 1]!;
  const lastLabel = `<text class="val" x="${(x(pts.length - 1) + 8).toFixed(1)}" y="${(y(last.score) + 4).toFixed(1)}">${last.score}</text>`;
  return `<svg viewBox="0 0 ${W} ${HGT}" role="img" aria-label="${esc(s.chartLabel(label))}">${grid}${xTicks}${path}${dots}${lastLabel}</svg>`;
}

export function renderHistoryHtml(h: History, lang: Lang = 'en'): string {
  const s = H[lang];
  const sections = h.targets.map((t) => {
    const label = s.target(t.source, t.context ?? s.defaultContext);
    const rows = t.points
      .map(
        (p) =>
          `<tr><td>${esc(stamp(p.scannedAt))}</td><td>${esc(p.score)}</td><td>${esc(deltaCell(p, s))}</td><td>${esc(p.findings)}</td><td>${esc(sevCell(p))}</td><td>${esc(p.controlsFailed)}</td><td><code>${esc(`${p.scannerVersion} (${p.gitSha.slice(0, 7)})`)}</code></td></tr>`,
      )
      .join('');
    return (
      `<section><h2>${esc(label)}</h2><p class="muted">${esc(trendLine(t, s))}</p><div class="chart-wrap">${chart(t, s, label)}</div>` +
      `<details open><summary>${esc(s.dataTable)}</summary><div class="table-wrap"><table><thead><tr>${s.cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div></details></section>`
    );
  });
  const skipped = h.skipped.length ? `<section><h2>${esc(s.skipped)}</h2><ul>${h.skipped.map((k) => `<li><code>${esc(k.file)}</code>: ${esc(k.reason)}</li>`).join('')}</ul></section>` : '';
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(s.title)}</title><style>${CSS}</style></head><body class="viz-root"><main><h1>${esc(s.title)}</h1>${
    h.targets.length ? sections.join('') : `<p>${esc(s.empty)}</p>`
  }${skipped}</main></body></html>\n`;
}
