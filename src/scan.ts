import { readFileSync } from 'node:fs';
import { ALL_CHECKS, SYSTEM_NAMESPACES, type Check } from './checks/index.js';
import { BENCHMARK, CONTROLS, MAPPING_DISCLAIMER } from './checks/controls.js';
import { loadKubeConfig, type KubeOptions } from './k8s/client.js';
import { fetchSnapshot } from './k8s/snapshot.js';
import { loadManifests } from './manifests.js';
import { scannerInfo } from './report/provenance.js';
import { attachFixes } from './remediation.js';
import { applySuppressions, type Suppression } from './suppressions.js';
import {
  SEVERITIES,
  type ClusterSnapshot,
  type ControlResult,
  type DataSource,
  type Finding,
  type Report,
  type ResourceRef,
  type Severity,
} from './types.js';

export interface ScanOptions extends KubeOptions {
  includeSystemNamespaces?: boolean;
  /** Extra namespaces to skip. */
  excludeNamespaces?: string[];
  now?: Date;
  /** Accepted-risk entries (see src/suppressions.ts). Expired ones are ignored and reported as warnings. */
  suppressions?: Suppression[];
  /** Drop findings below this severity before summarising, so summary/controls stay consistent with findings[]. */
  minSeverity?: Severity;
}

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3 };

export function resourceKey(r: ResourceRef): string {
  return [r.kind, r.namespace, r.name, r.container].filter(Boolean).join('/');
}

export function excludedNamespaces(opts: ScanOptions): string[] {
  const ex = new Set<string>(opts.includeSystemNamespaces ? [] : SYSTEM_NAMESPACES);
  for (const n of opts.excludeNamespaces ?? []) ex.add(n);
  return [...ex].sort();
}

/** Pure: snapshot in, report out. Deterministic apart from `scannedAt`. */
export function buildReport(
  snapshot: ClusterSnapshot,
  source: DataSource,
  opts: ScanOptions = {},
  checks: readonly Check[] = ALL_CHECKS,
): Report {
  const excluded = excludedNamespaces(opts);
  const ctx = { excludedNamespaces: new Set(excluded) };

  const byId = new Map<string, Finding>();
  for (const check of checks) {
    for (const raw of check.run(snapshot, ctx)) {
      const id = `${check.id}:${resourceKey(raw.resource)}`;
      if (byId.has(id)) continue; // replicas of one workload collapse to one finding
      const src = snapshot.sources?.[[raw.resource.kind, raw.resource.namespace, raw.resource.name].filter(Boolean).join('/')];
      byId.set(id, {
        id,
        checkId: check.id,
        title: check.title,
        severity: check.severity,
        category: check.category,
        resource: src ? { ...raw.resource, source: src } : raw.resource,
        evidence: raw.evidence,
        remediation: check.remediation,
        controls: check.controls,
      });
    }
  }
  const sevRank = (s: Severity) => SEVERITIES.indexOf(s);
  const floor = opts.minSeverity ? SEVERITIES.indexOf(opts.minSeverity) : SEVERITIES.length;
  const all = [...byId.values()].filter((f) => sevRank(f.severity) <= floor).sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id));
  attachFixes(all, snapshot);
  const sup = opts.suppressions ? applySuppressions(all, opts.suppressions, opts.now) : undefined;
  const findings = sup ? sup.active : all;

  const controlIds = [...new Set(checks.flatMap((c) => c.controls))].sort();
  const controls: ControlResult[] = controlIds.map((cid) => {
    const def = CONTROLS[cid];
    const findingIds = findings.filter((f) => f.controls.includes(cid)).map((f) => f.id);
    return {
      id: cid,
      title: def?.title ?? cid,
      benchmark: BENCHMARK,
      status: findingIds.length ? 'fail' : 'pass',
      findingIds,
      referenceMappings: { soc2: def?.soc2 ?? [], hipaa: def?.hipaa ?? [] },
    };
  });

  // Score = share of severity weight carried by passing checks. A check counts once however many resources fail it.
  const failedChecks = new Set(findings.map((f) => f.checkId));
  const totalWeight = checks.reduce((sum, c) => sum + SEVERITY_WEIGHT[c.severity], 0);
  const failedWeight = checks.filter((c) => failedChecks.has(c.id)).reduce((sum, c) => sum + SEVERITY_WEIGHT[c.severity], 0);
  const score = totalWeight ? Math.round((100 * (totalWeight - failedWeight)) / totalWeight) : 100;
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  const info = scannerInfo();

  return {
    schemaVersion: '1',
    source,
    provenance: {
      scanner: { name: 'noip', version: info.version, gitSha: info.gitSha },
      cluster: {
        serverVersion: snapshot.serverVersion.gitVersion,
        platform: snapshot.serverVersion.platform,
        context: snapshot.context,
        nodeCount: snapshot.nodeCount,
      },
      scannedAt: (opts.now ?? new Date()).toISOString(),
      checksRun: checks.map((c) => c.id),
      excludedNamespaces: excluded,
      ...(opts.minSeverity ? { minSeverity: opts.minSeverity } : {}),
    },
    summary: {
      score,
      findings: findings.length,
      bySeverity,
      checksFailed: failedChecks.size,
      controlsFailed: controls.filter((c) => c.status === 'fail').length,
      suppressed: sup?.suppressed.length ?? 0,
    },
    findings,
    controls,
    mappingDisclaimer: MAPPING_DISCLAIMER,
    ...(sup ? { suppressed: sup.suppressed } : {}),
    ...(sup?.warnings.length ? { warnings: sup.warnings } : {}),
  };
}

// fixtures/ sits at the package root; src/scan.ts and dist/scan.js are both one level below it.
const DEMO_FIXTURE = new URL('../fixtures/demo-cluster.json', import.meta.url);

export function loadDemoSnapshot(): ClusterSnapshot {
  return JSON.parse(readFileSync(DEMO_FIXTURE, 'utf8')) as ClusterSnapshot;
}

export function isDemoMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NOIP_DEMO === '1' || env.NOIP_DEMO === 'true';
}

/**
 * Scan the live cluster, or the bundled fixture when demo mode is explicitly requested.
 * Live failures throw K8sUnavailable — never a silent fallback to demo data.
 */
export async function getSnapshot(
  opts: ScanOptions & { demo?: boolean; manifests?: string[] } = {},
): Promise<{ snapshot: ClusterSnapshot; source: DataSource }> {
  if (opts.demo) return { snapshot: loadDemoSnapshot(), source: 'demo' };
  if (opts.manifests?.length) return { snapshot: await loadManifests(opts.manifests), source: 'manifests' };
  return { snapshot: await fetchSnapshot(loadKubeConfig(opts)), source: 'live' };
}

export async function scan(opts: ScanOptions & { demo?: boolean; manifests?: string[] } = {}): Promise<Report> {
  const { snapshot, source } = await getSnapshot(opts);
  return buildReport(snapshot, source, opts);
}
