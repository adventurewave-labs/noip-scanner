// Regression tests for the fourth independent review (r27–r31). One test per confirmed defect;
// the metrics single-flight/backoff fixes (#1, #2) are covered in test/metrics.test.ts.
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseManifestText } from '../src/manifests.js';
import { evaluatePod } from '../src/psa.js';
import { writeBundle } from '../src/report/bundle.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderOscal } from '../src/report/oscal.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import type { V1Pod } from '@kubernetes/client-node';

const restrictedPod = (patch: string) => `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: app}
spec:
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: c
    image: x
    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}${patch}}
`;

describe('review 4', () => {
  it('YAML nulls are treated as absent, as the API server decodes them (#3)', async () => {
    const pod = (y: string) => (parseManifestText(y, 'x.yaml') as Array<{ obj: V1Pod }>)[0]!.obj;
    // null hostPort / procMount no longer count as set
    const withPort = pod(restrictedPod('').replace('image: x', 'image: x\n    ports: [{containerPort: 80, hostPort: null}]'));
    expect(evaluatePod(withPort).level).toBe('restricted');
    expect(evaluatePod(pod(restrictedPod(', procMount: null'))).level).toBe('restricted');
    // container runAsNonRoot: null must not mask a missing pod-level value
    const y = restrictedPod(', runAsNonRoot: null').replace('runAsNonRoot: true, ', '');
    expect(evaluatePod(pod(y)).level).toBe('baseline');
    // and directly, without the manifest loader
    expect(evaluatePod({ spec: { containers: [{ name: 'c', securityContext: { runAsNonRoot: null as unknown as boolean } }] } }).restricted.join()).toMatch(/runAsNonRoot/);
  });

  it('no automatic NS-001 fix for a namespace with no pods to judge by (#4)', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    const def = r.findings.find((f) => f.id === 'NOIP-NS-001:Namespace/default')!;
    expect(r.podSecurity!.namespaces.find((n) => n.namespace === 'default')!.pods).toBe(0);
    expect(def.fix).toBeUndefined();
  });

  it('OSCAL: a control whose findings are all suppressed is not "satisfied", and the accepted risk is evidence (#5)', () => {
    const base = buildReport(loadDemoSnapshot(), 'demo');
    const ctrl = base.controls.find((c) => c.status === 'fail')!;
    const suppressions = ctrl.findingIds.map((id) => ({ id, reason: 'compensating control', owner: 'sre', expires: '2099-01-01' }));
    const r = buildReport(loadDemoSnapshot(), 'demo', { suppressions });
    expect(r.controls.find((c) => c.id === ctrl.id)!.status).toBe('pass'); // NOIP's own view: no active finding
    const doc = renderOscal(r) as { 'assessment-results': { results: Array<{ findings: Array<{ title: string; description: string; target: { status: { state: string } }; 'related-observations'?: unknown[] }>; observations: Array<{ remarks: string; props: Array<{ name: string; value: string }> }> }> } };
    const res = doc['assessment-results'].results[0]!;
    const f = res.findings.find((x) => x.title.startsWith(`${ctrl.id}:`))!;
    expect(f.target.status.state).toBe('not-satisfied');
    expect(f.description).toMatch(/accepted as risk \(suppressed\)/);
    expect(f['related-observations']).toHaveLength(ctrl.findingIds.length);
    const accepted = res.observations.filter((o) => o.props.some((p) => p.name === 'accepted-risk'));
    expect(accepted.length).toBeGreaterThanOrEqual(ctrl.findingIds.length);
    expect(accepted[0]!.remarks).toContain('reason "compensating control", owner sre, expires 2099-01-01');
  });

  it('markdown escapes policyVersion and the imported sha from untrusted reports (#6, #7)', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.podSecurity!.policyVersion = '<img src=x onerror=alert(1)>\n\n[click](javascript:alert(1))';
    r.imported = [{ tool: 't', inputFile: 'f.sarif', inputSha256: '`<img src=y>', results: [] } as never];
    const md = renderMarkdown(r);
    expect(md).not.toMatch(/<img src=[xy]|\]\(javascript/);
  });

  it('a bad signing key fails before anything is written (#8)', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const dir = join(mkdtempSync(join(tmpdir(), 'noip-r4-')), 'b');
    expect(() => writeBundle(dir, buildReport(loadDemoSnapshot(), 'demo'), 'en', { signKeyPem: rsa })).toThrow(/unsupported signing key/);
    expect(existsSync(dir)).toBe(false);
  });
});
