import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fixManifests } from '../src/fix.js';
import { loadManifests } from '../src/manifests.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { hardenedPod, ns, snap } from './helpers.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'noip-fix-'));
const covered = [{ metadata: { name: 'np', namespace: 'app' }, spec: { podSelector: {} } }];

describe('remediation patches', () => {
  it('attaches JSON Patch fixes with the right pod-spec prefix per workload kind', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    const fix = (id: string) => r.findings.find((f) => f.id === id)?.fix;
    expect(fix('NOIP-POD-002:DaemonSet/monitoring/node-exporter')).toEqual({ description: 'Remove hostPID from the pod spec.', patch: [{ op: 'remove', path: '/spec/template/spec/hostPID' }] });
    expect(fix('NOIP-POD-007:Deployment/shop/frontend/frontend')!.patch).toEqual([{ op: 'replace', path: '/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem', value: true }]);
    // debug-shell has privileged:true -> POD-005 fix must also drop privileged (API rejects the combination)
    expect(fix('NOIP-POD-005:Pod/ci/debug-shell/shell')!.patch).toEqual([
      { op: 'replace', path: '/spec/containers/0/securityContext/privileged', value: false },
      { op: 'add', path: '/spec/containers/0/securityContext/allowPrivilegeEscalation', value: false },
    ]);
    // init container index + no securityContext at all -> add the whole object
    expect(fix('NOIP-POD-006:Deployment/payments/api/migrate')!.patch[0]!.path).toBe('/spec/template/spec/initContainers/0/securityContext/runAsNonRoot');
    // NS-001 enforces the highest level today's pods already meet (never one that would reject them):
    // namespace without labels: create the map (RFC 6902 add needs the parent)
    expect(fix('NOIP-NS-001:Namespace/default')!.patch).toEqual([{ op: 'add', path: '/metadata/labels', value: { 'pod-security.kubernetes.io/enforce': 'restricted' } }]);
    expect(fix('NOIP-NS-001:Namespace/payments')!.patch).toEqual([{ op: 'add', path: '/metadata/labels', value: { 'pod-security.kubernetes.io/enforce': 'baseline' } }]);
    // pods below baseline (privileged debug shell, hostPID exporter): no automatic fix
    expect(fix('NOIP-NS-001:Namespace/ci')).toBeUndefined();
    expect(fix('NOIP-NS-001:Namespace/monitoring')).toBeUndefined();
    // namespace with labels: add the key
    const labelled = buildReport(snap({ namespaces: [{ metadata: { name: 'app', labels: { team: 'a' } } }], networkPolicies: covered, pods: [hardenedPod()] }), 'live');
    expect(labelled.findings.find((f) => f.checkId === 'NOIP-NS-001')!.fix!.patch).toEqual([{ op: 'add', path: '/metadata/labels/pod-security.kubernetes.io~1enforce', value: 'baseline' }]);
    // advisory only
    expect(fix('NOIP-NET-001:Namespace/ci')).toBeUndefined();
    expect(fix('NOIP-POD-008:Deployment/shop/frontend/frontend')).toBeUndefined();
  });

  it('creates securityContext when missing and skips ephemeral containers', () => {
    const pod = hardenedPod('app', 'p', (p) => {
      delete p.spec!.containers[0]!.securityContext;
      p.spec!.ephemeralContainers = [{ name: 'dbg', image: 'x', securityContext: { privileged: true } }];
    });
    const r = buildReport(snap({ namespaces: ns('app'), networkPolicies: covered, pods: [pod] }), 'live');
    const byCheck = Object.fromEntries(r.findings.map((f) => [`${f.checkId}/${f.resource.container}`, f.fix]));
    // POD-005 and POD-007 both create securityContext: each op carries the union so neither clobbers the other
    const union = { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true };
    expect(byCheck['NOIP-POD-005/c']!.patch).toEqual([{ op: 'add', path: '/spec/containers/0/securityContext', value: union }]);
    expect(byCheck['NOIP-POD-007/c']!.patch).toEqual([{ op: 'add', path: '/spec/containers/0/securityContext', value: union }]);
    expect(byCheck['NOIP-POD-001/dbg']).toBeUndefined();
  });
});

describe('noip fix', () => {
  it('fixes what it can, preserves comments and unrelated docs, and a re-scan leaves only advisory findings', async () => {
    const dir = tmp();
    cpSync(new URL('./fixtures/misconfig', import.meta.url).pathname, join(dir, 'k8s'), { recursive: true });
    const out = join(dir, 'fixed');
    const r = await fixManifests(['k8s'], { outDir: out, cwd: dir });
    // NS-001 in noip-test-bad is left for review: its pods don't meet baseline, so enforcing would reject them.
    expect(r.applied.map((a) => a.findingId).sort()).toEqual([
      'NOIP-POD-001:Pod/noip-test-bad/privileged/app',
      'NOIP-POD-002:Pod/noip-test-bad/hostpid',
      'NOIP-POD-005:Pod/noip-test-bad/privileged/app',
    ]);
    expect(r.advisory.map((f) => f.checkId).sort()).toEqual(['NOIP-NET-001', 'NOIP-NS-001', 'NOIP-POD-009', 'NOIP-RBAC-002']);
    const patched = readFileSync(join(out, 'k8s/10-bad-pods.yaml'), 'utf8');
    expect(patched).toContain('# hostPID: true -> NOIP-POD-002 (CIS-5.2.2)'); // comments kept
    expect(patched).not.toMatch(/^\s*hostPID: true/m);
    const rescan = buildReport(await loadManifests([join(out, 'k8s')]), 'manifests');
    expect(rescan.findings.map((f) => f.checkId).sort()).toEqual(['NOIP-NET-001', 'NOIP-NS-001', 'NOIP-POD-009', 'NOIP-RBAC-002']);
    // With the pods fixed they now meet baseline, so a second `noip fix` pass can safely label the namespace.
    expect(rescan.findings.find((f) => f.checkId === 'NOIP-NS-001')!.fix!.patch[0]!.value).toEqual({ 'pod-security.kubernetes.io/enforce': 'baseline' });
  });

  it('patches objects inside a List and is idempotent in place', async () => {
    const dir = tmp();
    writeFileSync(
      join(dir, 'list.yaml'),
      'apiVersion: v1\nkind: List\nitems:\n  - apiVersion: apps/v1\n    kind: Deployment\n    metadata: {name: w, namespace: n}\n    spec:\n      template:\n        spec:\n          hostNetwork: true\n          containers: []\n',
    );
    const first = await fixManifests(['list.yaml'], { inPlace: true, cwd: dir });
    expect(first.applied.map((a) => a.findingId)).toEqual(['NOIP-POD-004:Deployment/n/w']);
    expect(readFileSync(join(dir, 'list.yaml'), 'utf8')).not.toContain('hostNetwork');
    const second = await fixManifests(['list.yaml'], { inPlace: true, cwd: dir });
    expect(second.applied).toEqual([]);
  });

  it('honours suppressions and validates arguments', async () => {
    const dir = tmp();
    writeFileSync(join(dir, 'p.yaml'), 'apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: a}\nspec: {hostPID: true, containers: []}\n');
    const r = await fixManifests(['p.yaml'], { outDir: 'o', cwd: dir, suppressions: [{ check: 'NOIP-POD-002', reason: 'node debugging agent', owner: 'sre', expires: '2099-01-01' }] });
    expect(r.applied).toEqual([]);
    await expect(fixManifests(['-'], { outDir: 'o' })).rejects.toThrow(/needs files/);
    await expect(fixManifests(['p.yaml'], { cwd: dir })).rejects.toThrow(/exactly one/);
    await expect(fixManifests(['p.yaml'], { cwd: dir, outDir: 'o', inPlace: true })).rejects.toThrow(/exactly one/);
  });
});
