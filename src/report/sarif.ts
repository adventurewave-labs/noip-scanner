import type { Log, ReportingDescriptor, Result } from 'sarif';
import { ALL_CHECKS, type Check } from '../checks/index.js';
import { REFERENCES } from '../checks/references.js';
import { resourceKey } from '../scan.js';
import type { Finding, Report, Severity } from '../types.js';

/** GitHub code scanning reads `security-severity` (0–10) to bucket alerts; keep in step with our four levels. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };
const LEVEL: Record<Severity, Result.level> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

function rule(c: Check): ReportingDescriptor {
  return {
    id: c.id,
    name: c.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().replace(/ (\w)/g, (_, ch: string) => ch.toUpperCase()).replace(/^\w/, (ch) => ch.toUpperCase()),
    shortDescription: { text: c.title },
    fullDescription: { text: `${c.title}. ${c.remediation}` },
    help: {
      text: `${c.remediation}${c.controls.length ? `\nControls (reference mapping, not an attestation): ${c.controls.join(', ')}` : ''}`,
      markdown: `**Remediation:** ${c.remediation}${c.controls.length ? `\n\n**Controls** (reference mapping, not an attestation): ${c.controls.join(', ')}` : ''}`,
    },
    defaultConfiguration: { level: LEVEL[c.severity] },
    properties: {
      tags: ['security', 'kubernetes', c.category.toLowerCase().replace(/\s+/g, '-'), ...c.controls, ...(REFERENCES[c.id]?.nist800190.map((x) => `NIST-800-190 ${x.split(' ')[0]}`) ?? [])],
      'security-severity': SECURITY_SEVERITY[c.severity],
      precision: 'very-high',
      ...(REFERENCES[c.id] ? { references: REFERENCES[c.id] } : {}),
    },
  };
}

/**
 * Where a finding "lives". Manifest scans carry a real file (and line when known); live-cluster findings get a stable
 * pseudo-path `k8s/<Kind>/<namespace>/<name>` so code-scanning UIs can group and de-duplicate them across runs.
 */
function location(f: Finding): Result['locations'] {
  const src = f.resource.source;
  const pseudo = `k8s/${[f.resource.kind, f.resource.namespace, f.resource.name].filter(Boolean).join('/')}`;
  // `<stdin>` is not a valid URI reference; fall back to the pseudo-path but keep the line number.
  const uri = src?.file && src.file !== '<stdin>' ? src.file : pseudo;
  return [
    {
      physicalLocation: { artifactLocation: { uri }, ...(src?.line ? { region: { startLine: src.line } } : {}) },
      logicalLocations: [{ fullyQualifiedName: resourceKey(f.resource), kind: 'resource' }],
    },
  ];
}

/** SARIF 2.1.0 — consumable by GitHub code scanning, Azure DevOps, VS Code SARIF Viewer, DefectDojo, etc. */
export function renderSarif(r: Report, checks: readonly Check[] = ALL_CHECKS): Log {
  const ran = new Set(r.provenance.checksRun);
  const rules = checks.filter((c) => ran.has(c.id)).map(rule);
  const index = new Map(rules.map((ru, i) => [ru.id, i]));
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'noip',
            semanticVersion: r.provenance.scanner.version,
            informationUri: 'https://github.com/adventurewave-labs/noip-scanner',
            rules,
          },
        },
        automationDetails: { id: `noip/${r.source}/${r.provenance.cluster.context ?? 'default'}/` },
        versionControlProvenance: r.provenance.scanner.gitSha !== 'unknown' ? [{ repositoryUri: 'https://github.com/adventurewave-labs/noip-scanner', revisionId: r.provenance.scanner.gitSha }] : undefined,
        invocations: [{ executionSuccessful: true, endTimeUtc: r.provenance.scannedAt }],
        properties: {
          source: r.source,
          kubernetesVersion: r.provenance.cluster.serverVersion,
          ...(r.provenance.cluster.versionSupport ? { kubernetesSupport: r.provenance.cluster.versionSupport } : {}),
          score: r.summary.score,
          mappingDisclaimer: r.mappingDisclaimer,
        },
        results: [
          ...r.findings.map((f) => toResult(f, index, r.source)),
          // Suppressed findings stay visible as SARIF suppressions (status accepted) so tools show them as dismissed.
          ...(r.suppressed ?? []).map((x) => ({
            ...toResult(x.finding, index, r.source),
            suppressions: [{ kind: 'external' as const, status: 'accepted' as const, justification: `${x.suppression.reason} (owner ${x.suppression.owner}, expires ${x.suppression.expires})` }],
          })),
        ],
      },
      // Imported runs are re-emitted as their own SARIF runs, attributed to the original tool.
      ...(r.imported ?? []).map((run) => ({
        tool: { driver: { name: run.tool, ...(run.version ? { semanticVersion: run.version } : {}), informationUri: 'https://github.com/adventurewave-labs/noip-scanner' } },
        properties: { importedBy: 'noip', inputFile: run.inputFile, inputSha256: run.inputSha256 },
        results: run.results.map((x) => ({
          ruleId: x.ruleId,
          level: LEVEL[x.severity],
          message: { text: x.message || x.ruleId },
          ...(x.location ? { locations: [{ physicalLocation: { artifactLocation: { uri: x.location.uri }, ...(x.location.line ? { region: { startLine: x.location.line } } : {}) } }] } : {}),
          properties: { 'security-severity': SECURITY_SEVERITY[x.severity] },
        })),
      })),
    ],
  };
}

function toResult(f: Finding, index: Map<string, number>, source: string): Result {
  return {
    ruleId: f.checkId,
    ruleIndex: index.get(f.checkId),
    level: LEVEL[f.severity],
    message: { text: `${f.title}: ${f.evidence}` },
    locations: location(f),
    // Stable across runs so re-scans update rather than duplicate alerts.
    partialFingerprints: { 'noipFindingId/v1': f.id },
    properties: { severity: f.severity, controls: f.controls, source },
  };
}
