import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { ImportedRun, Severity } from '../types.js';

/**
 * Merge other scanners' SARIF (Trivy, kubescape, Checkov, KICS…) into the report as `imported[]`.
 * Imported results never change NOIP's score or control status; they sit alongside, attributed to
 * their tool, so one report can carry the whole picture (ADR-0004: wrap, don't grow our check set).
 */
const Result = z.object({
  ruleId: z.string().optional(),
  level: z.enum(['none', 'note', 'warning', 'error']).optional(),
  message: z.object({ text: z.string().optional(), markdown: z.string().optional() }).passthrough(),
  locations: z
    .array(
      z.object({
        physicalLocation: z
          .object({ artifactLocation: z.object({ uri: z.string().optional() }).passthrough().optional(), region: z.object({ startLine: z.number().int().optional() }).passthrough().optional() })
          .passthrough()
          .optional(),
      }).passthrough(),
    )
    .optional(),
  suppressions: z.array(z.object({}).passthrough()).optional(),
  properties: z.record(z.string(), z.unknown()).optional(),
}).passthrough();

const Rule = z.object({ id: z.string(), defaultConfiguration: z.object({ level: z.string().optional() }).passthrough().optional(), properties: z.record(z.string(), z.unknown()).optional() }).passthrough();

const SarifLog = z.object({
  version: z.literal('2.1.0'),
  runs: z.array(
    z.object({
      tool: z.object({ driver: z.object({ name: z.string(), version: z.string().optional(), semanticVersion: z.string().optional(), rules: z.array(Rule).optional() }).passthrough() }).passthrough(),
      results: z.array(Result).max(20_000).optional(),
    }).passthrough(),
  ).max(50),
}).passthrough();

/** GitHub's security-severity buckets, falling back to the SARIF level. */
function severityOf(score: unknown, level: string | undefined): Severity {
  const n = typeof score === 'string' ? Number(score) : typeof score === 'number' ? score : NaN;
  if (!Number.isNaN(n)) return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low';
  return level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'low';
}

export function importSarif(raw: string, file: string): ImportedRun[] {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new Error(`--import-sarif ${file}: not valid JSON (${(err as Error).message})`, { cause: err });
  }
  const res = SarifLog.safeParse(json);
  if (!res.success) throw new Error(`--import-sarif ${file}: not SARIF 2.1.0 (${res.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')})`);
  const sha = createHash('sha256').update(raw).digest('hex');
  return res.data.runs.map((run) => {
    const rules = new Map((run.tool.driver.rules ?? []).map((r) => [r.id, r]));
    const results = (run.results ?? [])
      .filter((r) => !r.suppressions?.length) // the tool itself already accepted these
      .map((r) => {
        const rule = r.ruleId ? rules.get(r.ruleId) : undefined;
        const level = r.level ?? (rule?.defaultConfiguration?.level as string | undefined) ?? 'warning';
        const loc = r.locations?.[0]?.physicalLocation;
        return {
          ruleId: r.ruleId ?? 'unknown',
          severity: severityOf(r.properties?.['security-severity'] ?? rule?.properties?.['security-severity'], level),
          message: (r.message.text ?? r.message.markdown ?? '').slice(0, 2000),
          ...(loc?.artifactLocation?.uri ? { location: { uri: loc.artifactLocation.uri, ...(loc.region?.startLine ? { line: loc.region.startLine } : {}) } } : {}),
        };
      })
      .filter((r) => r.severity !== undefined);
    return {
      tool: run.tool.driver.name,
      version: run.tool.driver.semanticVersion ?? run.tool.driver.version,
      inputFile: file,
      inputSha256: sha,
      results,
    };
  });
}
