import {
  CoreV1Api,
  NetworkingV1Api,
  RbacAuthorizationV1Api,
  VersionApi,
  type KubeConfig,
  type V1Service,
} from '@kubernetes/client-node';
import { K8sUnavailable } from '../errors.js';
import type { ClusterSnapshot } from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;

function statusOf(err: unknown): number | undefined {
  const e = err as { code?: unknown; statusCode?: unknown; response?: { statusCode?: unknown } };
  for (const v of [e?.code, e?.statusCode, e?.response?.statusCode]) {
    if (typeof v === 'number' && v >= 100 && v < 600) return v;
  }
  return undefined;
}

async function call<T>(what: string, p: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new K8sUnavailable(`${what}: timed out after ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    return await Promise.race([p, timeout]);
  } catch (err) {
    if (err instanceof K8sUnavailable) throw err;
    const status = statusOf(err);
    const msg = (err as Error)?.message?.split('\n')[0] ?? String(err);
    throw new K8sUnavailable(`${what} failed${status ? ` (HTTP ${status})` : ''}: ${msg}`, status);
  } finally {
    clearTimeout(timer);
  }
}

export const PAGE_SIZE = 500;
const MAX_PAGES = 1000; // 500k objects: far beyond any sane cluster; guards against a server that never ends the list

interface Page<T> {
  items: T[];
  metadata?: { _continue?: string };
}

/**
 * Chunked LIST (limit/continue), so very large clusters don't need one giant response.
 * On 410 Gone (continue token expired mid-list) the list restarts once from scratch for a consistent result.
 */
export async function listAll<T>(what: string, fetchPage: (p: { limit: number; _continue?: string }) => Promise<Page<T>>, timeoutMs: number): Promise<T[]> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const items: T[] = [];
    let token: string | undefined;
    try {
      for (let page = 0; page < MAX_PAGES; page++) {
        const res = await call(what, fetchPage({ limit: PAGE_SIZE, ...(token ? { _continue: token } : {}) }), timeoutMs);
        items.push(...res.items);
        token = res.metadata?._continue || undefined;
        if (!token) return items;
      }
      throw new K8sUnavailable(`${what}: more than ${MAX_PAGES} pages; refusing to continue`);
    } catch (err) {
      if (err instanceof K8sUnavailable && err.httpStatus === 410 && attempt === 0) continue;
      throw err;
    }
  }
  /* v8 ignore next */
  throw new K8sUnavailable(`${what}: list kept expiring`);
}

/**
 * Fetch every list the checks need, exactly once. Any failure raises K8sUnavailable;
 * there is deliberately no fixture fallback (PRD R-3).
 * Needs only get/list on: namespaces, pods, nodes, networkpolicies, clusterrolebindings, rolebindings
 * (see deploy/rbac.yaml). Secrets are never read.
 */
export async function fetchSnapshot(kc: KubeConfig, timeoutMs = Number(process.env.NOIP_K8S_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS): Promise<ClusterSnapshot> {
  const core = kc.makeApiClient(CoreV1Api);
  const net = kc.makeApiClient(NetworkingV1Api);
  const rbac = kc.makeApiClient(RbacAuthorizationV1Api);
  const version = kc.makeApiClient(VersionApi);

  const [v, nodes, namespaces, pods, netpols, crbs, rbs, sas, svcs] = await Promise.all([
    call('GET /version', version.getCode(), timeoutMs),
    listAll('list nodes', (p) => core.listNode(p), timeoutMs),
    listAll('list namespaces', (p) => core.listNamespace(p), timeoutMs),
    listAll('list pods', (p) => core.listPodForAllNamespaces(p), timeoutMs),
    listAll('list networkpolicies', (p) => net.listNetworkPolicyForAllNamespaces(p), timeoutMs),
    listAll('list clusterrolebindings', (p) => rbac.listClusterRoleBinding(p), timeoutMs),
    listAll('list rolebindings', (p) => rbac.listRoleBindingForAllNamespaces(p), timeoutMs),
    listAll('list serviceaccounts', (p) => core.listServiceAccountForAllNamespaces(p), timeoutMs),
    listAll('list services', (p) => core.listServiceForAllNamespaces(p), timeoutMs),
  ]);

  return {
    serverVersion: { gitVersion: v.gitVersion, platform: v.platform },
    context: kc.getCurrentContext() || undefined,
    nodeCount: nodes.length,
    namespaces,
    pods,
    networkPolicies: netpols,
    clusterRoleBindings: crbs,
    roleBindings: rbs,
    // Keep only what risk chains use: never token references or image pull secret names.
    serviceAccounts: sas.map((s) => ({ metadata: { name: s.metadata?.name, namespace: s.metadata?.namespace }, automountServiceAccountToken: s.automountServiceAccountToken })),
    services: svcs.map(minimalService),
  };
}

/** Keep only what exposure analysis needs. */
export const minimalService = (s: V1Service): V1Service => ({
  metadata: { name: s.metadata?.name, namespace: s.metadata?.namespace },
  spec: { type: s.spec?.type, selector: s.spec?.selector, ...(s.spec?.externalIPs?.length ? { externalIPs: s.spec.externalIPs } : {}) },
});

/** Cheap reachability probe for /health: one GET /version. */
export async function probeVersion(kc: KubeConfig, timeoutMs = 3000): Promise<string> {
  const v = await call('GET /version', kc.makeApiClient(VersionApi).getCode(), timeoutMs);
  return v.gitVersion;
}
