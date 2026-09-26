import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PREDICATE_TYPE, STATEMENT_FILE, SUMS_FILE, verifyBundle, writeBundle } from '../src/report/bundle.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const report = () => buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-09-26T00:00:00Z') });
const fresh = () => {
  const d = join(mkdtempSync(join(tmpdir(), 'noip-bundle-')), 'b');
  writeBundle(d, report());
  return d;
};

describe('evidence bundle', () => {
  it('writes all formats, SHA256SUMS (sha256sum -c compatible) and an in-toto v1 statement', () => {
    const d = fresh();
    const sums = readFileSync(join(d, SUMS_FILE), 'utf8');
    expect(sums.trim().split('\n').map((l) => l.split('  ')[1])).toEqual([STATEMENT_FILE, 'report.html', 'report.json', 'report.md', 'report.oscal.json', 'report.sarif']);
    expect(execFileSync('sha256sum', ['-c', SUMS_FILE], { cwd: d }).toString()).toMatch(/report\.json: OK/);
    const st = JSON.parse(readFileSync(join(d, STATEMENT_FILE), 'utf8'));
    expect(st._type).toBe('https://in-toto.io/Statement/v1');
    expect(st.predicateType).toBe(PREDICATE_TYPE);
    expect(st.subject.map((s: { name: string }) => s.name)).toEqual(['report.json', 'report.md', 'report.html', 'report.sarif', 'report.oscal.json']);
    expect(st.predicate).toMatchObject({ source: 'demo', scanner: { gitSha: 'test-sha' }, scannedAt: '2026-09-26T00:00:00.000Z' });
    expect(verifyBundle(d)).toEqual({ ok: true, problems: [], files: 6, signature: 'unsigned' });
  });

  it('refuses to write into a non-empty directory', () => {
    const d = fresh();
    expect(() => writeBundle(d, report())).toThrow(/not empty/);
  });

  it('detects tampering, missing and extra files, and subject/provenance mismatches', () => {
    const d1 = fresh();
    appendFileSync(join(d1, 'report.md'), 'x');
    expect(verifyBundle(d1).problems).toEqual(['hash mismatch: report.md']);

    const d2 = fresh();
    rmSync(join(d2, 'report.html'));
    writeFileSync(join(d2, 'extra.txt'), 'x');
    expect(verifyBundle(d2).problems).toEqual(['missing file: report.html', 'file not covered by SHA256SUMS: extra.txt']);

    const d3 = fresh();
    rmSync(join(d3, SUMS_FILE));
    expect(verifyBundle(d3)).toEqual({ ok: false, problems: ['SHA256SUMS missing'], files: 0, signature: 'unsigned' });

    // Consistently re-hashed but provenance swapped: caught by the cross-check.
    const d4 = fresh();
    const r = JSON.parse(readFileSync(join(d4, 'report.json'), 'utf8'));
    r.provenance.scannedAt = '2020-01-01T00:00:00.000Z';
    writeFileSync(join(d4, 'report.json'), JSON.stringify(r));
    const sha = execFileSync('sha256sum', ['report.json'], { cwd: d4 }).toString().split(' ')[0];
    const sums = readFileSync(join(d4, SUMS_FILE), 'utf8').replace(/^[0-9a-f]{64}(?= {2}report\.json$)/m, sha!);
    writeFileSync(join(d4, SUMS_FILE), sums);
    expect(verifyBundle(d4).problems).toEqual([
      'in-toto subject does not match SHA256SUMS: report.json',
      'report.json provenance does not match the in-toto predicate',
    ]);
  });

  it('rejects malformed or path-traversing SHA256SUMS entries', () => {
    const d = fresh();
    writeFileSync(join(d, SUMS_FILE), `${'a'.repeat(64)}  ../etc/passwd\nnot a line\n` + readFileSync(join(d, SUMS_FILE), 'utf8'));
    const p = verifyBundle(d).problems;
    expect(p).toContain('unsafe path in SHA256SUMS: ../etc/passwd');
    expect(p).toContain('malformed line in SHA256SUMS: not a line');
  });

  it('reports an unreadable statement', () => {
    const d = fresh();
    writeFileSync(join(d, STATEMENT_FILE), '{');
    expect(verifyBundle(d).problems.some((p) => p.startsWith('cannot read provenance.intoto.json'))).toBe(true);
  });
});
