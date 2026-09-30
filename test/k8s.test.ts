import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CoreV1Api, KubeConfig, NetworkingV1Api, RbacAuthorizationV1Api, VersionApi } from '@kubernetes/client-node';
import { describe, expect, it } from 'vitest';
import { K8sUnavailable } from '../src/errors.js';
import { loadKubeConfig } from '../src/k8s/client.js';
import { fetchSnapshot, probeVersion } from '../src/k8s/snapshot.js';

const KUBECONFIG = `apiVersion: v1
kind: Config
clusters:
  - name: c
    cluster: { server: https://127.0.0.1:6443, insecure-skip-tls-verify: true }
users:
  - name: u
    user: { token: t }
contexts:
  - name: ctx-a
    context: { cluster: c, user: u }
  - name: ctx-b
    context: { cluster: c, user: u }
current-context: ctx-a
`;

function kubeconfigFile(): string {
  const f = join(mkdtempSync(join(tmpdir(), 'noip-kc-')), 'config');
  writeFileSync(f, KUBECONFIG);
  return f;
}

/** A KubeConfig whose API clients are fakes keyed by class. */
function fakeKc(apis: Map<unknown, object>): KubeConfig {
  const kc = new KubeConfig();
  kc.loadFromString(KUBECONFIG);
  kc.makeApiClient = ((cls: unknown) => apis.get(cls)) as KubeConfig['makeApiClient'];
  return kc;
}

const list = <T>(items: T[]) => async () => ({ items });

describe('loadKubeConfig', () => {
  it('loads an explicit file and switches context', () => {
    const f = kubeconfigFile();
    expect(loadKubeConfig({ kubeconfig: f }).getCurrentContext()).toBe('ctx-a');
    expect(loadKubeConfig({ kubeconfig: f, context: 'ctx-b' }).getCurrentContext()).toBe('ctx-b');
  });
  it('raises K8sUnavailable for a missing file, unknown context or no kubeconfig', () => {
    expect(() => loadKubeConfig({ kubeconfig: '/nonexistent' })).toThrow(K8sUnavailable);
    expect(() => loadKubeConfig({ kubeconfig: kubeconfigFile(), context: 'nope' })).toThrow(/context "nope" not found/);
    const prev = process.env.KUBECONFIG;
    process.env.KUBECONFIG = '/nonexistent/a';
    try {
      expect(() => loadKubeConfig()).toThrow(/no kubeconfig found/);
    } finally {
      if (prev === undefined) delete process.env.KUBECONFIG;
      else process.env.KUBECONFIG = prev;
    }
  });
});

describe('fetchSnapshot', () => {
  const ok = () =>
    new Map<unknown, object>([
      [VersionApi, { getCode: async () => ({ gitVersion: 'v1.31.2', platform: 'linux/arm64' }) }],
      [
        CoreV1Api,
        {
          listNode: list([{}, {}]),
          listNamespace: list([{ metadata: { name: 'a' } }]),
          listPodForAllNamespaces: list([]),
          listServiceForAllNamespaces: list([{ metadata: { name: 'web', namespace: 'a', annotations: { secret: 'x' } }, spec: { type: 'LoadBalancer', selector: { app: 'web' }, ports: [{ port: 80 }], clusterIP: '10.0.0.1' } }]),
          listServiceAccountForAllNamespaces: list([{ metadata: { name: 'default', namespace: 'a', uid: 'u' }, automountServiceAccountToken: false, secrets: [{ name: 'default-token-x' }], imagePullSecrets: [{ name: 'regcred' }] }]),
        },
      ],
      [NetworkingV1Api, { listNetworkPolicyForAllNamespaces: list([]) }],
      [RbacAuthorizationV1Api, { listClusterRoleBinding: list([]), listRoleBindingForAllNamespaces: list([]) }],
    ]);

  it('fetches every list once and records version from the /version API', async () => {
    const s = await fetchSnapshot(fakeKc(ok()));
    expect(s).toMatchObject({ serverVersion: { gitVersion: 'v1.31.2', platform: 'linux/arm64' }, context: 'ctx-a', nodeCount: 2 });
    expect(s.namespaces).toHaveLength(1);
    // only name, namespace and the automount flag are kept: no token or pull-secret references
    expect(s.services).toEqual([{ metadata: { name: 'web', namespace: 'a' }, spec: { type: 'LoadBalancer', selector: { app: 'web' } } }]);
    expect(s.serviceAccounts).toEqual([{ metadata: { name: 'default', namespace: 'a' }, automountServiceAccountToken: false }]);
    expect(await probeVersion(fakeKc(ok()))).toBe('v1.31.2');
  });

  it('turns API errors into K8sUnavailable with the HTTP status', async () => {
    const apis = ok();
    apis.set(CoreV1Api, { ...apis.get(CoreV1Api), listPodForAllNamespaces: async () => { throw Object.assign(new Error('forbidden: pods is forbidden'), { code: 403 }); } });
    const err = await fetchSnapshot(fakeKc(apis)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(K8sUnavailable);
    expect((err as K8sUnavailable).httpStatus).toBe(403);
    expect((err as Error).message).toBe('list pods failed (HTTP 403): forbidden: pods is forbidden');
  });

  it('times out slow calls', async () => {
    const apis = ok();
    apis.set(VersionApi, { getCode: () => new Promise(() => {}) });
    await expect(fetchSnapshot(fakeKc(apis), 20)).rejects.toThrow(/timed out after 20ms/);
  });
});
