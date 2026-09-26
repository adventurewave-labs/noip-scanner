import {
  CoreV1Api,
  NetworkingV1Api,
  RbacAuthorizationV1Api,
  VersionApi,
  type KubeConfig,
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

  const [v, nodes, namespaces, pods, netpols, crbs, rbs] = await Promise.all([
    call('GET /version', version.getCode(), timeoutMs),
    call('list nodes', core.listNode(), timeoutMs),
    call('list namespaces', core.listNamespace(), timeoutMs),
    call('list pods', core.listPodForAllNamespaces(), timeoutMs),
    call('list networkpolicies', net.listNetworkPolicyForAllNamespaces(), timeoutMs),
    call('list clusterrolebindings', rbac.listClusterRoleBinding(), timeoutMs),
    call('list rolebindings', rbac.listRoleBindingForAllNamespaces(), timeoutMs),
  ]);

  return {
    serverVersion: { gitVersion: v.gitVersion, platform: v.platform },
    context: kc.getCurrentContext() || undefined,
    nodeCount: nodes.items.length,
    namespaces: namespaces.items,
    pods: pods.items,
    networkPolicies: netpols.items,
    clusterRoleBindings: crbs.items,
    roleBindings: rbs.items,
  };
}

/** Cheap reachability probe for /health: one GET /version. */
export async function probeVersion(kc: KubeConfig, timeoutMs = 3000): Promise<string> {
  const v = await call('GET /version', kc.makeApiClient(VersionApi).getCode(), timeoutMs);
  return v.gitVersion;
}
