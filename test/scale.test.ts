import type { V1Pod } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { K8sUnavailable } from '../src/errors.js';
import { listAll, PAGE_SIZE } from '../src/k8s/snapshot.js';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport } from '../src/scan.js';
import { applySuppressions } from '../src/suppressions.js';
import { snap } from './helpers.js';

/** A synthetic 10k-pod cluster: 500 namespaces x 20 pods, a mix of Deployment replicas and bare pods, ~half misconfigured. */
export function bigCluster(namespaces = 500, podsPerNs = 20) {
  const pods: V1Pod[] = [];
  for (let n = 0; n < namespaces; n++) {
    for (let i = 0; i < podsPerNs; i++) {
      const deploy = i < podsPerNs / 2;
      pods.push({
        metadata: {
          name: deploy ? `web-7f9c-${i}` : `job-${i}`,
          namespace: `ns-${n}`,
          ...(deploy ? { labels: { 'pod-template-hash': '7f9c' }, ownerReferences: [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-7f9c', uid: 'u', controller: true }] } : {}),
        },
        spec: {
          hostNetwork: i % 7 === 0,
          containers: [
            { name: 'app', image: 'x', securityContext: i % 2 ? { privileged: true } : { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true }, resources: {} },
            { name: 'sidecar', image: 'y', env: [{ name: 'T', valueFrom: { secretKeyRef: { name: 's', key: 'k' } } }] },
          ],
        },
      });
    }
  }
  return snap({
    nodeCount: 200,
    namespaces: Array.from({ length: namespaces }, (_, n) => ({ metadata: { name: `ns-${n}` } })),
    networkPolicies: Array.from({ length: namespaces / 2 }, (_, n) => ({ metadata: { name: 'np', namespace: `ns-${n * 2}` }, spec: { podSelector: {}, egress: [{}] } })),
    pods,
  });
}

describe('scale', () => {
  it('scans a 10k-pod / 500-namespace cluster and renders every format within budget', () => {
    const s = bigCluster();
    expect(s.pods).toHaveLength(10_000);
    const t0 = performance.now();
    const r = buildReport(s, 'live');
    const tScan = performance.now() - t0;
    renderMarkdown(r);
    renderHtml(r);
    renderSarif(r);
    const tAll = performance.now() - t0;
    // Deployment replicas collapse: 10 replicas per namespace -> 1 workload.
    expect(r.findings.some((f) => f.id === 'NOIP-POD-008:Deployment/ns-0/web/app')).toBe(true);
    expect(r.findings.filter((f) => f.resource.kind === 'Deployment' && f.resource.namespace === 'ns-0' && f.checkId === 'NOIP-POD-008')).toHaveLength(2);
    expect(r.findings.length).toBeGreaterThan(10_000);
    // Generous budgets for shared CI runners; locally this is ~10x faster.
    expect(tScan).toBeLessThan(4000);
    expect(tAll).toBeLessThan(10_000);
  });

  it('applies 200 suppressions to tens of thousands of findings quickly', () => {
    const r = buildReport(bigCluster(), 'live');
    const sup = Array.from({ length: 200 }, (_, i) => ({ check: 'NOIP-POD-009', resource: `Pod/ns-${i}/**`, reason: 'accepted in bulk for test', owner: 'o', expires: '2099-01-01' }));
    const t0 = performance.now();
    const out = applySuppressions(r.findings, sup);
    expect(performance.now() - t0).toBeLessThan(4000);
    expect(out.suppressed.length).toBe(200 * 10);
  });
});

describe('paginated LIST', () => {
  const pages = (total: number) => {
    const calls: Array<{ limit: number; _continue?: string }> = [];
    const fetchPage = async (p: { limit: number; _continue?: string }) => {
      calls.push(p);
      const start = p._continue ? Number(p._continue) : 0;
      const end = Math.min(total, start + p.limit);
      return { items: Array.from({ length: end - start }, (_, i) => start + i), metadata: { _continue: end < total ? String(end) : '' } };
    };
    return { calls, fetchPage };
  };

  it('follows continue tokens until the list is complete', async () => {
    const { calls, fetchPage } = pages(1234);
    const items = await listAll('list pods', fetchPage, 1000);
    expect(items).toHaveLength(1234);
    expect(items[1233]).toBe(1233);
    expect(calls.map((c) => c._continue)).toEqual([undefined, String(PAGE_SIZE), String(PAGE_SIZE * 2)]);
    expect(calls.every((c) => c.limit === PAGE_SIZE)).toBe(true);
  });

  it('restarts once on 410 Gone (expired continue token), then gives up', async () => {
    let n = 0;
    const flaky = async (p: { limit: number; _continue?: string }) => {
      n++;
      if (p._continue && n === 2) throw Object.assign(new Error('Expired: too old resource version'), { code: 410 });
      return { items: [p._continue ?? 'first'], metadata: { _continue: p._continue ? '' : 'tok' } };
    };
    expect(await listAll('list pods', flaky, 1000)).toEqual(['first', 'tok']);
    const always410 = async (p: { limit: number; _continue?: string }) => {
      if (p._continue) throw Object.assign(new Error('Expired'), { code: 410 });
      return { items: [1], metadata: { _continue: 'tok' } };
    };
    await expect(listAll('list pods', always410, 1000)).rejects.toMatchObject({ httpStatus: 410 });
  });

  it('refuses a server that never ends the list', async () => {
    const endless = async () => ({ items: [], metadata: { _continue: 'again' } });
    await expect(listAll('list pods', endless, 1000)).rejects.toBeInstanceOf(K8sUnavailable);
  });
});
