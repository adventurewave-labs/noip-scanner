import { createHash } from 'node:crypto';
import { resourceKey } from '../scan.js';
import type { Report } from '../types.js';

/**
 * OSCAL Assessment Results (NIST OSCAL 1.2.3, JSON): the scan as machine-readable assessment evidence
 * for GRC tools. Validated in tests against the official schema (schemas/vendor/).
 *
 * Honest scope: control IDs are CIS Kubernetes Benchmark IDs as NOIP maps them (see mappingDisclaimer),
 * not an imported OSCAL catalog, and there is no assessment plan or SSP to import. `import-ap` points at a
 * back-matter resource that says so. One observation per finding; one OSCAL finding per mapped control.
 * UUIDs are deterministic (v5) so the same report always produces the same document.
 */
export const OSCAL_VERSION = '1.2.3';
/** Namespace URI for NOIP-specific OSCAL props. */
const NOIP_NS = 'https://github.com/adventurewave-labs/noip-scanner/ns/oscal';
const NS = 'b9f6a1e2-4c3d-5e7f-8a9b-0c1d2e3f4a5b'; // fixed namespace for NOIP's v5 UUIDs

export function uuidv5(name: string, namespace = NS): string {
  const ns = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const h = createHash('sha1').update(ns).update(name, 'utf8').digest();
  h[6] = (h[6]! & 0x0f) | 0x50;
  h[8] = (h[8]! & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

/** OSCAL tokens are NCNames: start with a letter or underscore; letters, digits, '.', '-', '_' after. */
export const token = (s: string) => {
  const t = s.toLowerCase().replace(/[^\p{L}\p{N}._-]+/gu, '-');
  return /^[\p{L}_]/u.test(t) ? t : `_${t}`;
};

export function renderOscal(r: Report): object {
  const seed = `${r.source}|${r.provenance.cluster.context ?? ''}|${r.provenance.scannedAt}|${r.provenance.scanner.gitSha}`;
  const id = (kind: string, key = '') => uuidv5(`${seed}|${kind}|${key}`);
  const apResource = id('assessment-plan');
  const at = r.provenance.scannedAt;

  const resources = [...new Map(r.findings.map((f) => [resourceKey(f.resource), f.resource])).entries()].sort(([a], [b]) => a.localeCompare(b));
  const inventory = resources.map(([key, res]) => ({
    uuid: id('inventory', key),
    description: `Kubernetes ${res.kind} ${key}`,
    props: [
      { name: 'kubernetes-kind', ns: NOIP_NS, value: res.kind },
      ...(res.namespace ? [{ name: 'kubernetes-namespace', ns: NOIP_NS, value: res.namespace }] : []),
    ],
  }));

  const observations = r.findings.map((f) => ({
    uuid: id('observation', f.id),
    title: `${f.checkId}: ${f.title}`,
    description: f.evidence,
    props: [
      { name: 'noip-finding-id', ns: NOIP_NS, value: token(f.id) },
      { name: 'severity', ns: NOIP_NS, value: f.severity },
    ],
    methods: ['TEST'],
    types: ['finding'],
    subjects: [{ 'subject-uuid': id('inventory', resourceKey(f.resource)), type: 'inventory-item', title: resourceKey(f.resource) }],
    collected: at,
    remarks: f.remediation,
  }));
  const obsByFinding = new Map(r.findings.map((f, i) => [f.id, observations[i]!.uuid]));

  // Suppressed findings are not in r.findings, so a control can list IDs with no observation here.
  const related = (ids: string[]) => {
    const refs = ids.flatMap((fid) => (obsByFinding.has(fid) ? [{ 'observation-uuid': obsByFinding.get(fid)! }] : []));
    return refs.length ? { 'related-observations': refs } : {};
  };
  const findings = r.controls.map((c) => ({
    uuid: id('finding', c.id),
    title: `${c.id}: ${c.title}`,
    description:
      c.status === 'pass'
        ? `No NOIP check mapped to ${c.id} produced a finding.`
        : `${c.findingIds.length} NOIP finding(s) mapped to ${c.id}.`,
    target: {
      type: 'objective-id',
      'target-id': token(`${c.id}_obj`),
      status: { state: c.status === 'pass' ? 'satisfied' : 'not-satisfied' },
    },
    ...related(c.findingIds),
  }));

  const result = {
    uuid: id('result'),
    title: `NOIP posture scan (${r.source})`,
    description: `Read-only Kubernetes posture scan of ${r.provenance.cluster.context ?? r.source}: score ${r.summary.score}/100, ${r.summary.findings} finding(s).`,
    start: at,
    end: at,
    props: [{ name: 'noip-source', ns: NOIP_NS, value: r.source }],
    ...(inventory.length ? { 'local-definitions': { 'inventory-items': inventory } } : {}),
    'reviewed-controls': {
      'control-selections': [
        r.controls.length ? { 'include-controls': r.controls.map((c) => ({ 'control-id': token(c.id) })) } : { 'include-all': {} },
      ],
    },
    ...(observations.length ? { observations } : {}),
    ...(findings.length ? { findings } : {}),
    remarks: r.mappingDisclaimer,
  };

  return JSON.parse(
    JSON.stringify({
      'assessment-results': {
        uuid: id('assessment-results'),
        metadata: {
          title: 'NOIP Kubernetes posture assessment results',
          'last-modified': at,
          version: `${r.provenance.scanner.version}+${r.provenance.scanner.gitSha.slice(0, 12)}`,
          'oscal-version': OSCAL_VERSION,
          remarks: 'Generated by NOIP from a scan report. Control IDs are CIS Kubernetes Benchmark IDs as mapped by NOIP, not an imported catalog.',
        },
        'import-ap': { href: `#${apResource}` },
        results: [result],
        'back-matter': {
          resources: [
            {
              uuid: apResource,
              title: 'NOIP check catalog (no separate assessment plan)',
              description: `The assessment method is NOIP's fixed set of ${r.provenance.checksRun.length} read-only checks (${r.provenance.checksRun.join(', ')}). No OSCAL assessment plan or SSP was imported.`,
            },
          ],
        },
      },
    }),
  ) as object;
}
