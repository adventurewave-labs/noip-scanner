import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { K8sUnavailable } from './errors.js';
import { loadKubeConfig } from './k8s/client.js';
import { renderHtml } from './report/html.js';
import type { Lang } from './report/i18n.js';
import { renderMarkdown } from './report/markdown.js';
import { renderOscal } from './report/oscal.js';
import { renderSarif } from './report/sarif.js';
import { buildReport, getSnapshot, type ScanOptions } from './scan.js';
import type { Report, Severity } from './types.js';

/**
 * Scan several kubeconfig contexts in one run (one report per cluster + a fleet summary).
 * One unreachable cluster never hides the others: it is recorded and the run continues.
 */
export interface FleetEntry {
  context: string;
  status: 'ok' | 'unreachable';
  error?: string;
  file?: string;
  serverVersion?: string;
  score?: number;
  findings?: number;
  bySeverity?: Record<Severity, number>;
  controlsFailed?: number;
}
export interface Fleet {
  generatedAt: string;
  clusters: FleetEntry[];
}

type Format = 'json' | 'md' | 'sarif' | 'html' | 'oscal';
const EXT: Record<Format, string> = { json: 'json', md: 'md', sarif: 'sarif', html: 'html', oscal: 'oscal.json' };
/** Report file stem for a context. Prefixed so no context can collide with fleet.json / fleet.md. */
export const safeName = (ctx: string) => `cluster-${ctx.replace(/[^A-Za-z0-9._-]+/g, '_')}`;

export function allContexts(kubeconfig?: string): string[] {
  return loadKubeConfig({ kubeconfig }).getContexts().map((c) => c.name);
}

export async function scanFleet(
  contexts: string[],
  opts: ScanOptions & { outDir: string; format: Format; now?: Date; lang?: Lang },
  snap: typeof getSnapshot = getSnapshot,
): Promise<{ fleet: Fleet; reports: Report[] }> {
  if (!contexts.length) throw new Error('no contexts to scan');
  // Case-insensitive: macOS and Windows file systems would silently overwrite `Prod` with `prod`.
  if (new Set(contexts.map((c) => safeName(c).toLowerCase())).size !== contexts.length) throw new Error('context names collide after sanitising; scan them separately');
  mkdirSync(opts.outDir, { recursive: true });
  const fleet: Fleet = { generatedAt: (opts.now ?? new Date()).toISOString(), clusters: [] };
  const reports: Report[] = [];
  for (const context of contexts) {
    try {
      const { snapshot, source } = await snap({ ...opts, context });
      const r = buildReport(snapshot, source, opts);
      const file = `${safeName(context)}.${EXT[opts.format]}`;
      const body =
        opts.format === 'md' ? renderMarkdown(r, opts.lang) : opts.format === 'html' ? renderHtml(r, opts.lang) : JSON.stringify(opts.format === 'sarif' ? renderSarif(r) : opts.format === 'oscal' ? renderOscal(r) : r, null, 2) + '\n';
      writeFileSync(join(opts.outDir, file), body);
      reports.push(r);
      fleet.clusters.push({
        context,
        status: 'ok',
        file,
        serverVersion: r.provenance.cluster.serverVersion,
        score: r.summary.score,
        findings: r.summary.findings,
        bySeverity: r.summary.bySeverity,
        controlsFailed: r.summary.controlsFailed,
      });
    } catch (err) {
      if (!(err instanceof K8sUnavailable)) throw err;
      fleet.clusters.push({ context, status: 'unreachable', error: err.message });
    }
  }
  writeFileSync(join(opts.outDir, 'fleet.json'), JSON.stringify(fleet, null, 2) + '\n');
  writeFileSync(join(opts.outDir, 'fleet.md'), renderFleetMarkdown(fleet));
  return { fleet, reports };
}

export function renderFleetMarkdown(f: Fleet): string {
  const rows = f.clusters.map((c) =>
    c.status === 'ok'
      ? `| ${c.context} | ✅ | ${c.serverVersion} | ${c.score}/100 | ${c.bySeverity!.critical} | ${c.bySeverity!.high} | ${c.bySeverity!.medium} | ${c.bySeverity!.low} | [${c.file}](${c.file}) |`
      : `| ${c.context} | ❌ unreachable | — | — | — | — | — | — | ${c.error!.replace(/\|/g, '\\|')} |`,
  );
  const ok = f.clusters.filter((c) => c.status === 'ok');
  const worst = ok.reduce<FleetEntry | undefined>((w, c) => (!w || c.score! < w.score! ? c : w), undefined);
  return [
    '# NOIP fleet posture',
    '',
    `Generated ${f.generatedAt} · ${ok.length}/${f.clusters.length} cluster(s) scanned${worst ? ` · lowest score: **${worst.context}** (${worst.score}/100)` : ''}`,
    '',
    '| Context | Status | Kubernetes | Score | Critical | High | Medium | Low | Report |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows,
    '',
  ].join('\n');
}
