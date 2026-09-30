import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { V1Pod } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { evaluatePod, PSA_LATEST_MINOR } from '../src/psa.js';

const ROOT = 'test/fixtures/psa';
const versions = readdirSync(join(ROOT, 'baseline')).sort();

describe('Pod Security Standards: upstream conformance fixtures', () => {
  it('covers the vendored versions', () => expect(versions).toEqual(['v1.23', 'v1.25', 'v1.30', 'v1.34', 'v1.35', 'v1.37']));

  for (const level of ['baseline', 'restricted'] as const) {
    for (const v of versions) {
      const minor = Number(v.split('.')[1]);
      for (const outcome of ['pass', 'fail'] as const) {
        it(`${level} ${v} ${outcome}`, () => {
          const dir = join(ROOT, level, v, outcome);
          const files = readdirSync(dir);
          expect(files.length).toBeGreaterThan(0);
          const wrong: string[] = [];
          for (const f of files) {
            const got = evaluatePod(parse(readFileSync(join(dir, f), 'utf8')) as V1Pod, minor).level;
            const ok =
              level === 'baseline' ? (outcome === 'pass' ? got !== 'privileged' : got === 'privileged') : outcome === 'pass' ? got === 'restricted' : got !== 'restricted';
            if (!ok) wrong.push(`${f} → ${got}`);
          }
          expect(wrong).toEqual([]);
        });
      }
    }
  }

  it('evaluates newer clusters with the latest known policy and reports reasons', () => {
    const pod = parse(readFileSync(join(ROOT, 'baseline/v1.37/fail/privileged0.yaml'), 'utf8')) as V1Pod;
    const r = evaluatePod(pod, 99);
    expect(r.level).toBe('privileged');
    expect(r.baseline.join()).toMatch(/privileged containers/);
    expect(evaluatePod({ spec: undefined, metadata: undefined })).toMatchObject({ level: 'restricted' });
    expect(PSA_LATEST_MINOR).toBe(37);
    // old clusters are evaluated with the oldest implemented policy (1.23)
    expect(evaluatePod(pod, 10).level).toBe('privileged');
  });

  it('checks the deprecated AppArmor annotation and restricted rules for Windows pods', () => {
    const base = parse(readFileSync(join(ROOT, 'restricted/v1.37/pass/base.yaml'), 'utf8')) as V1Pod;
    expect(evaluatePod(base).level).toBe('restricted');
    const ann = (v: string) => evaluatePod({ ...base, metadata: { ...base.metadata, annotations: { 'container.apparmor.security.beta.kubernetes.io/container1': v } } }).level;
    expect(ann('runtime/default')).toBe('restricted');
    expect(ann('localhost/custom')).toBe('restricted');
    expect(ann('unconfined')).toBe('privileged');
    const typed = (type: string) => evaluatePod({ ...base, spec: { ...base.spec!, securityContext: { ...base.spec!.securityContext, appArmorProfile: { type } } } }).level;
    expect(typed('RuntimeDefault')).toBe('restricted');
    expect(typed('Unconfined')).toBe('privileged');
    expect(evaluatePod({ metadata: {}, spec: {} as V1Pod['spec'] }).level).toBe('restricted');
  });
});

describe('Pod Security readiness in reports', () => {
  it('computes per-namespace readiness with blockers, and renders it escaped in en/es', async () => {
    const { buildReport, loadDemoSnapshot } = await import('../src/scan.js');
    const { renderMarkdown } = await import('../src/report/markdown.js');
    const { renderHtml } = await import('../src/report/html.js');
    const r = buildReport(loadDemoSnapshot(), 'demo');
    const by = Object.fromEntries(r.podSecurity!.namespaces.map((n) => [n.namespace, n]));
    expect(r.podSecurity!.policyVersion).toBe('1.31');
    expect(by.shop).toMatchObject({ enforce: 'restricted', canEnforce: 'restricted', blockers: [] });
    expect(by.payments).toMatchObject({ canEnforce: 'baseline', blockers: [{ resource: 'Deployment/payments/api', level: 'restricted' }] });
    expect(by.ci!.canEnforce).toBe('privileged');
    expect(by.monitoring!.blockers.map((b) => b.resource)).toEqual([...by.monitoring!.blockers.map((b) => b.resource)].sort());
    const md = renderMarkdown(r);
    expect(md).toContain('## Pod Security readiness');
    expect(md).toMatch(/\| payments \| not set \| \*\*baseline\*\* \| 1 \| \*\*Deployment\/payments\/api\*\*: pod or containers must set runAsNonRoot=true/);
    expect(renderMarkdown(r, 'es')).toContain('## Preparación para Pod Security');
    // untrusted report content (noip render) stays inert
    r.podSecurity!.namespaces[0]!.namespace = '<img src=x>|';
    (r.podSecurity!.namespaces[0] as unknown as Record<string, unknown>).canEnforce = '`<b>`';
    expect(renderHtml(r)).not.toContain('<img src=x>');
    expect(renderMarkdown(r)).not.toMatch(/<img src=x>|<b>/);
  });

  it('is omitted when there is nothing to evaluate, and caps the policy version', async () => {
    const { buildReport } = await import('../src/scan.js');
    const { snap } = await import('./helpers.js');
    expect(buildReport(snap(), 'live').podSecurity).toBeUndefined();
    const r = buildReport(snap({ serverVersion: { gitVersion: 'v1.40.1', platform: 'linux/amd64' }, pods: [{ metadata: { name: 'p', namespace: 'x' }, spec: { containers: [] } }] }), 'live');
    expect(r.podSecurity!.policyVersion).toBe('1.37');
    const m = buildReport(snap({ serverVersion: { gitVersion: 'n/a' }, pods: [{ metadata: { name: 'p' }, spec: { containers: [] } }] }), 'manifests');
    expect(m.podSecurity!.namespaces[0]).toMatchObject({ namespace: 'default', canEnforce: 'restricted' });
  });
});

describe('podSecurityReadiness', () => {
  it('collapses replicas into one blocker per workload and sorts blockers', async () => {
    const { podSecurityReadiness } = await import('../src/psa.js');
    const bad = (name: string, owner: string) => ({ metadata: { name, namespace: 'n', labels: { owner } }, spec: { hostPID: true, containers: [{ name: 'c' }] } }) as V1Pod;
    const r = podSecurityReadiness([bad('b-1', 'b'), bad('a-1', 'a'), bad('b-2', 'b')], [{ metadata: { name: 'n', labels: { 'pod-security.kubernetes.io/enforce': 'baseline' } } }], new Set(), (p) => `Deployment/n/${p.metadata!.labels!.owner}`);
    expect(r.namespaces[0]).toMatchObject({ enforce: 'baseline', pods: 3, canEnforce: 'privileged' });
    expect(r.namespaces[0]!.blockers.map((b) => b.resource)).toEqual(['Deployment/n/a', 'Deployment/n/b']);
  });
});
