import { describe, expect, it } from 'vitest';
import { loadManifests, ManifestError, parseManifestText } from '../src/manifests.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport } from '../src/scan.js';
import { golden } from './helpers.js';

const fx = (p: string) => new URL(`./fixtures/${p}`, import.meta.url).pathname;

describe('manifest scanning (shift-left)', () => {
  it('reproduces the kind golden from the same YAML, offline', async () => {
    const r = buildReport(await loadManifests([fx('misconfig')]), 'manifests');
    expect(r.source).toBe('manifests');
    expect(r.findings.map((f) => f.id).sort()).toEqual([...golden.expectedFindingIds].sort());
    expect(r.findings.every((f) => f.resource.source?.file.includes('test/fixtures/misconfig/'))).toBe(true);
  });

  it('expands workload templates (incl. CronJob inside a List) and records file:line', async () => {
    const r = buildReport(await loadManifests([fx('manifests/app.yaml')]), 'manifests');
    const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
    expect(byId['NOIP-POD-001:Deployment/shop/api/api']!.resource.source).toEqual({ file: expect.stringMatching(/app\.yaml$/), line: 2 });
    expect(byId['NOIP-POD-004:CronJob/shop/nightly']!.resource.source!.line).toBe(18);
    // hardened CronJob container: only the hostNetwork finding
    expect(r.findings.filter((f) => f.resource.name === 'nightly').map((f) => f.checkId)).toEqual(['NOIP-POD-004']);
    // SARIF points at the real file
    const uri = renderSarif(r).runs[0]!.results![0]!.locations![0]!.physicalLocation!.artifactLocation!.uri;
    expect(uri).toMatch(/app\.yaml$/);
  });

  it('reads stdin for "-" and defaults missing namespaces to "default"', async () => {
    const s = await loadManifests(['-'], async () => 'apiVersion: v1\nkind: Pod\nmetadata: { name: p }\nspec: { hostPID: true, containers: [] }\n');
    expect(s.pods[0]!.metadata!.namespace).toBe('default');
    expect(s.sources!['Pod/default/p']).toEqual({ file: '<stdin>', line: 1 });
  });

  it('keeps the first declaration of a duplicated object', async () => {
    const dup = 'apiVersion: v1\nkind: Namespace\nmetadata: { name: a }\n';
    const s = await loadManifests(['-', '-'], async () => dup);
    expect(s.namespaces).toHaveLength(1);
  });

  it('fails clearly on bad YAML or missing paths', async () => {
    expect(() => parseManifestText('a: [unclosed', 'bad.yaml')).toThrow(ManifestError);
    await expect(loadManifests(['/nonexistent/dir'])).rejects.toThrow(/cannot read \/nonexistent\/dir \(ENOENT\)/);
  });

  it('ignores non-Kubernetes documents and empty docs', () => {
    expect(parseManifestText('---\nfoo: bar\n---\n', 'x.yaml').map((d) => d.obj)).toEqual([{ foo: 'bar' }]);
  });
});

describe('every workload kind is expanded', () => {
  it.each(['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'ReplicationController', 'Job'])('%s', async (kind) => {
    const y = `apiVersion: apps/v1\nkind: ${kind}\nmetadata: { name: w, namespace: n }\nspec:\n  template:\n    spec:\n      hostIPC: true\n      containers: []\n`;
    const r = buildReport(await loadManifests(['-'], async () => y), 'manifests');
    expect(r.findings.map((f) => f.id)).toEqual([`NOIP-POD-003:${kind}/n/w`]);
  });
  it('skips workloads without a pod template', async () => {
    const s = await loadManifests(['-'], async () => 'apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: w }\nspec: {}\n');
    expect(s.pods).toEqual([]);
  });
});

describe('scan()', () => {
  it('runs end to end for demo and manifests', async () => {
    const { scan } = await import('../src/scan.js');
    expect((await scan({ demo: true })).source).toBe('demo');
    expect((await scan({ manifests: [fx('misconfig')] })).source).toBe('manifests');
  });
});

describe('hostile YAML (found by fuzzing)', () => {
  it('turns unresolved aliases into a ManifestError', () => {
    expect(() => parseManifestText('*!', 'x.yaml')).toThrow(ManifestError);
  });
  it('refuses alias bombs instead of expanding them', () => {
    const bomb = ['a: &a ["x","x","x","x","x","x","x","x","x"]', ...'bcdefghi'.split('').map((c, i) => `${c}: &${c} [${Array(9).fill(`*${'abcdefghi'[i]}`).join(',')}]`)].join('\n');
    expect(() => parseManifestText(bomb, 'bomb.yaml')).toThrow(ManifestError);
  });
});
