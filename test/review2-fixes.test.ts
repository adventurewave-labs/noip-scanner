// Regression tests for the second independent review (loop 2).
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fixManifests } from '../src/fix.js';
import { scanFleet } from '../src/fleet.js';
import { loadManifests } from '../src/manifests.js';
import { verifyBundle, writeBundle, STATEMENT_FILE, SUMS_FILE } from '../src/report/bundle.js';
import { importSarif } from '../src/report/import-sarif.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'noip-r2-'));

describe('review 2 fixes', () => {
  it('noip fix applies every securityContext fix on a container that had none', async () => {
    const dir = tmp();
    writeFileSync(join(dir, 'd.yaml'), 'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: app}\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: x\n');
    const r = await fixManifests(['d.yaml'], { inPlace: true, cwd: dir });
    expect(r.applied.map((a) => a.findingId.split(':')[0]).sort()).toEqual(['NOIP-POD-005', 'NOIP-POD-006', 'NOIP-POD-007']);
    const rescan = buildReport(await loadManifests([join(dir, 'd.yaml')]), 'manifests');
    expect(rescan.findings.map((f) => f.checkId).filter((c) => ['NOIP-POD-005', 'NOIP-POD-006', 'NOIP-POD-007'].includes(c))).toEqual([]);
  });

  it('noip fix reports findings it cannot locate instead of dropping them', async () => {
    const dir = tmp();
    writeFileSync(join(dir, 'j.yaml'), 'apiVersion: batch/v1\nkind: Job\nmetadata: {generateName: mig-, namespace: a}\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers: []\n');
    const r = await fixManifests(['j.yaml'], { outDir: '../out-' + Date.now(), cwd: dir });
    expect(r.applied).toEqual([]);
    expect(r.advisory.map((f) => f.checkId)).toContain('NOIP-POD-004');
  });

  it('noip fix refuses an --out-dir inside an input directory', async () => {
    const dir = tmp();
    mkdirSync(join(dir, 'k8s'));
    writeFileSync(join(dir, 'k8s/p.yaml'), 'apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {hostPID: true, containers: []}\n');
    await expect(fixManifests(['k8s'], { outDir: 'k8s/fixed', cwd: dir })).rejects.toThrow(/inside the input/);
    await expect(fixManifests(['k8s'], { outDir: 'k8s', cwd: dir })).rejects.toThrow(/inside the input/);
  });

  it('markdown neutralises hostile imported SARIF (no headings, links or HTML injected)', () => {
    const evil = JSON.stringify({
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'trivy\n\n## Score: 100/100' } }, results: [{ ruleId: 'R1\n\n[click](https://evil.example)', message: { text: '<img src=x onerror=alert(1)> `x`' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a|b' } } }] }] }],
    });
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.imported = importSarif(evil, 'evil`.sarif');
    const md = renderMarkdown(r);
    expect(md).not.toMatch(/^## Score/m);
    expect(md).not.toContain('](https://evil');
    expect(md).not.toContain('<img');
    expect(md).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(md).toContain('a\\|b');
    expect(md).toContain('From `` evil`.sarif ``');
  });

  it('fleet report files can never collide with fleet.json', async () => {
    const dir = join(tmp(), 'f');
    const { fleet } = await scanFleet(['fleet', 'prod'], { outDir: dir, format: 'json' }, async () => ({ snapshot: loadDemoSnapshot(), source: 'live' }));
    expect(fleet.clusters.map((c) => c.file)).toEqual(['cluster-fleet.json', 'cluster-prod.json']);
    expect(JSON.parse(readFileSync(join(dir, 'fleet.json'), 'utf8')).clusters).toHaveLength(2);
  });

  it('verify-bundle rejects symlinks and files that are not in-toto subjects', () => {
    const base = tmp();
    const d = join(base, 'b');
    writeBundle(d, buildReport(loadDemoSnapshot(), 'demo'));
    writeFileSync(join(base, 'outside.txt'), 'x');
    // swap report.md for a symlink pointing outside the bundle
    const md = readFileSync(join(d, 'report.md'));
    writeFileSync(join(base, 'report.md.orig'), md);
    
    rmSync(join(d, 'report.md'));
    symlinkSync(join(base, 'outside.txt'), join(d, 'report.md'));
    expect(verifyBundle(d).problems).toContain('not a regular file (symlink or directory): report.md');

    const d2 = join(base, 'b2');
    writeBundle(d2, buildReport(loadDemoSnapshot(), 'demo'));
    writeFileSync(join(d2, 'extra.txt'), 'added after signing');
    
    const sha = createHash('sha256').update('added after signing').digest('hex');
    writeFileSync(join(d2, SUMS_FILE), readFileSync(join(d2, SUMS_FILE), 'utf8') + `${sha}  extra.txt\n`);
    expect(verifyBundle(d2).problems).toEqual([`${SUMS_FILE} lists a file that is not an in-toto subject: extra.txt`]);
    expect(STATEMENT_FILE).toBe('provenance.intoto.json');
  });
});
