import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Report } from '../types.js';
import { renderHtml } from './html.js';
import type { Lang } from './i18n.js';
import { renderMarkdown } from './markdown.js';
import { renderOscal } from './oscal.js';
import { renderSarif } from './sarif.js';

/**
 * Audit evidence bundle: every report format + SHA256SUMS + an in-toto v1 Statement binding the
 * files to the scan's provenance. Unsigned by design (no keys in the tool); sign it with your own
 * tooling, e.g. `cosign attest-blob`, if the engagement needs non-repudiation.
 */
export const PREDICATE_TYPE = 'https://github.com/adventurewave-labs/noip-scanner/attestation/scan/v1';
export const STATEMENT_FILE = 'provenance.intoto.json';
export const SUMS_FILE = 'SHA256SUMS';

const sha256 = (b: string | Buffer) => createHash('sha256').update(b).digest('hex');

export function bundleFiles(r: Report, lang: Lang = 'en'): Record<string, string> {
  return {
    'report.json': JSON.stringify(r, null, 2) + '\n',
    'report.md': renderMarkdown(r, lang),
    'report.html': renderHtml(r, lang),
    'report.sarif': JSON.stringify(renderSarif(r), null, 2) + '\n',
    'report.oscal.json': JSON.stringify(renderOscal(r), null, 2) + '\n',
  };
}

export function inTotoStatement(r: Report, digests: Record<string, string>) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: Object.entries(digests).map(([name, sha]) => ({ name, digest: { sha256: sha } })),
    predicateType: PREDICATE_TYPE,
    predicate: {
      source: r.source,
      scanner: r.provenance.scanner,
      cluster: r.provenance.cluster,
      scannedAt: r.provenance.scannedAt,
      checksRun: r.provenance.checksRun,
      excludedNamespaces: r.provenance.excludedNamespaces,
      summary: r.summary,
      mappingDisclaimer: r.mappingDisclaimer,
    },
  };
}

/** Write the bundle and return the SHA256SUMS content. Refuses to write into a non-empty directory. */
export function writeBundle(dir: string, r: Report, lang: Lang = 'en'): string {
  mkdirSync(dir, { recursive: true });
  if (readdirSync(dir).length) throw new Error(`--bundle: ${dir} is not empty; refusing to mix evidence from different scans`);
  const files = bundleFiles(r, lang);
  const digests: Record<string, string> = {};
  for (const [name, body] of Object.entries(files)) {
    writeFileSync(join(dir, name), body);
    digests[name] = sha256(body);
  }
  const statement = JSON.stringify(inTotoStatement(r, digests), null, 2) + '\n';
  writeFileSync(join(dir, STATEMENT_FILE), statement);
  digests[STATEMENT_FILE] = sha256(statement);
  // `sha256sum -c SHA256SUMS` compatible (two spaces, sorted).
  const sums = Object.keys(digests)
    .sort()
    .map((n) => `${digests[n]}  ${n}`)
    .join('\n') + '\n';
  writeFileSync(join(dir, SUMS_FILE), sums);
  return sums;
}

export interface BundleVerification {
  ok: boolean;
  problems: string[];
  files: number;
}

/** Recompute hashes, cross-check the in-toto subjects and the report's own provenance. */
export function verifyBundle(dir: string): BundleVerification {
  const problems: string[] = [];
  let sums: string;
  try {
    sums = readFileSync(join(dir, SUMS_FILE), 'utf8');
  } catch {
    return { ok: false, problems: [`${SUMS_FILE} missing`], files: 0 };
  }
  const entries = sums.trim().split('\n').filter(Boolean).map((l) => {
    const m = /^([0-9a-f]{64}) {2}(.+)$/.exec(l);
    if (!m) problems.push(`malformed line in ${SUMS_FILE}: ${l}`);
    return m ? { sha: m[1]!, name: m[2]! } : null;
  }).filter((e): e is { sha: string; name: string } => e !== null);
  for (const e of entries) {
    if (e.name.includes('/') || e.name.includes('..')) {
      problems.push(`unsafe path in ${SUMS_FILE}: ${e.name}`);
      continue;
    }
    try {
      // Never follow a symlink out of the bundle: only regular files count as evidence.
      if (!lstatSync(join(dir, e.name)).isFile()) {
        problems.push(`not a regular file (symlink or directory): ${e.name}`);
        continue;
      }
      if (sha256(readFileSync(join(dir, e.name))) !== e.sha) problems.push(`hash mismatch: ${e.name}`);
    } catch {
      problems.push(`missing file: ${e.name}`);
    }
  }
  const extra = readdirSync(dir).filter((f) => f !== SUMS_FILE && !entries.some((e) => e.name === f));
  for (const f of extra) problems.push(`file not covered by ${SUMS_FILE}: ${f}`);

  try {
    const st = JSON.parse(readFileSync(join(dir, STATEMENT_FILE), 'utf8')) as ReturnType<typeof inTotoStatement>;
    for (const s of st.subject) {
      const listed = entries.find((e) => e.name === s.name);
      if (!listed || listed.sha !== s.digest.sha256) problems.push(`in-toto subject does not match ${SUMS_FILE}: ${s.name}`);
    }
    // The statement is what gets signed: everything else in SHA256SUMS must be one of its subjects.
    const subjects = new Set([...st.subject.map((s) => s.name), STATEMENT_FILE]);
    for (const e of entries) if (!subjects.has(e.name)) problems.push(`${SUMS_FILE} lists a file that is not an in-toto subject: ${e.name}`);
    const r = JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8')) as Report;
    if (r.provenance.scannedAt !== st.predicate.scannedAt || r.provenance.scanner.gitSha !== st.predicate.scanner.gitSha) {
      problems.push('report.json provenance does not match the in-toto predicate');
    }
  } catch (err) {
    problems.push(`cannot read ${STATEMENT_FILE} or report.json: ${(err as Error).message}`);
  }
  return { ok: problems.length === 0, problems, files: entries.length };
}
