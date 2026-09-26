import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { imageInventory, parseImage, renderKbom } from '../src/report/kbom.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, snap } from './helpers.js';

const req = createRequire(import.meta.url);
type Validator = ((d: unknown) => boolean) & { errors?: unknown[] | null };
const Ajv = req('ajv') as new (o: object) => { addSchema: (s: object) => void; compile: (s: object) => Validator };
const addFormats = req('ajv-formats') as (a: unknown) => void;
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const load = (f: string) => JSON.parse(readFileSync(`schemas/vendor/${f}`, 'utf8'));
ajv.addSchema(load('cyclonedx-spdx.schema.json'));
ajv.addSchema(load('cyclonedx-jsf-0.82.schema.json'));
const validate = ajv.compile(load('cyclonedx-bom-1.6.schema.json'));
const valid = (d: unknown) => {
  const ok = validate(d);
  if (!ok) console.error(JSON.stringify(validate.errors?.slice(0, 5), null, 1));
  return ok;
};
const DIGEST = `sha256:${'a'.repeat(64)}`;

describe('image references', () => {
  it('parses Docker-style references with defaults', () => {
    expect(parseImage('nginx')).toEqual({ registry: 'docker.io', repository: 'library/nginx' });
    expect(parseImage('nginx:1.27')).toEqual({ registry: 'docker.io', repository: 'library/nginx', tag: '1.27' });
    expect(parseImage('bitnami/redis:7')).toEqual({ registry: 'docker.io', repository: 'bitnami/redis', tag: '7' });
    expect(parseImage('ghcr.io/org/app:v1@' + DIGEST)).toEqual({ registry: 'ghcr.io', repository: 'org/app', tag: 'v1', digest: DIGEST });
    expect(parseImage('localhost:5000/app')).toEqual({ registry: 'localhost:5000', repository: 'app' });
    expect(parseImage('localhost/app:dev')).toEqual({ registry: 'localhost', repository: 'app', tag: 'dev' });
  });

  it('inventories images per workload (replicas collapse), including init and ephemeral containers, skipping excluded namespaces', () => {
    const rs = (name: string) => hardenedPod('app', name, (p) => {
      p.metadata!.ownerReferences = [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-5d9f8c7b6', uid: 'u', controller: true }];
      p.spec!.initContainers = [{ name: 'init', image: 'busybox' }];
    });
    const dbg = hardenedPod('ops', 'd', (p) => (p.spec!.ephemeralContainers = [{ name: 'dbg', image: 'busybox' }]));
    const inv = imageInventory([rs('web-5d9f8c7b6-a'), rs('web-5d9f8c7b6-b'), dbg, hardenedPod('kube-system', 's')], new Set(['kube-system']));
    expect(inv).toEqual([
      { image: 'busybox', workloads: 2, namespaces: ['app', 'ops'] },
      { image: 'x', workloads: 2, namespaces: ['app', 'ops'] },
    ]);
  });
});

describe('KBOM (CycloneDX 1.6)', () => {
  it('validates against the official schema and describes the cluster and its images', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    const bom = renderKbom(r) as { components: Array<{ name: string; properties: Array<{ name: string; value: string }> }>; metadata: { component: { type: string; version: string } }; dependencies: Array<{ dependsOn: string[] }> };
    expect(valid(bom)).toBe(true);
    expect(bom.metadata.component).toMatchObject({ type: 'platform', version: 'v1.31.4' });
    expect(bom.components.length).toBe(r.inventory!.images.length);
    expect(bom.dependencies[0]!.dependsOn).toHaveLength(r.inventory!.images.length);
    expect(JSON.stringify(renderKbom(r))).toBe(JSON.stringify(bom)); // deterministic
  });

  it('adds purl and hash only for digest-pinned images, and stays valid for manifest scans and empty inventories', () => {
    const pinned = hardenedPod('app', 'p', (p) => (p.spec!.containers[0]!.image = `ghcr.io/Org/App:v1@${DIGEST}`));
    const bad = hardenedPod('app', 'q', (p) => (p.spec!.containers[0]!.image = 'x@sha256:nothex'));
    const r = buildReport(snap({ serverVersion: { gitVersion: 'n/a' }, context: undefined, pods: [pinned, bad] }), 'manifests');
    const bom = renderKbom(r) as { components: Array<{ purl?: string; hashes?: unknown[]; version?: string }>; metadata: { component: { name: string; version?: string } } };
    expect(valid(bom)).toBe(true);
    const [p1, p2] = bom.components;
    expect(p1!.purl).toBe(`pkg:oci/app@sha256%3A${'a'.repeat(64)}?repository_url=ghcr.io%2Forg%2Fapp&tag=v1`);
    expect(p1!.hashes).toEqual([{ alg: 'SHA-256', content: 'a'.repeat(64) }]);
    expect(p2).toMatchObject({ version: 'sha256:nothex' });
    expect(p2!.purl).toBeUndefined();
    expect(bom.metadata.component).toEqual(expect.objectContaining({ name: 'manifests' }));
    expect(bom.metadata.component.version).toBeUndefined();
    expect(valid(renderKbom(buildReport(snap(), 'live')))).toBe(true);
  });
});

describe('noip scan -o cyclonedx', () => {
  let out = '';
  beforeEach(() => {
    out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((s) => ((out += String(s)), true));
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());
  it('emits a valid BOM', async () => {
    await main(['node', 'noip', 'scan', '--demo', '-o', 'cyclonedx']);
    expect(valid(JSON.parse(out))).toBe(true);
  });
});
