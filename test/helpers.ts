import { readFileSync, readdirSync } from 'node:fs';
import type { V1ClusterRoleBinding, V1Namespace, V1NetworkPolicy, V1Pod, V1RoleBinding } from '@kubernetes/client-node';
import { parseAllDocuments } from 'yaml';
import type { ClusterSnapshot } from '../src/types.js';

export function snap(partial: Partial<ClusterSnapshot> = {}): ClusterSnapshot {
  return {
    serverVersion: { gitVersion: 'v1.31.0', platform: 'linux/amd64' },
    context: 'test',
    nodeCount: 1,
    namespaces: [],
    pods: [],
    networkPolicies: [],
    clusterRoleBindings: [],
    roleBindings: [],
    ...partial,
  };
}

/** A pod that passes every NOIP check. Override pieces to seed exactly one flaw. */
export function hardenedPod(ns = 'app', name = 'ok', patch: (p: V1Pod) => void = () => {}): V1Pod {
  const pod: V1Pod = {
    metadata: { name, namespace: ns },
    spec: {
      securityContext: { runAsNonRoot: true, runAsUser: 10001 },
      containers: [
        {
          name: 'c',
          image: 'x',
          securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true },
          resources: { limits: { cpu: '100m', memory: '64Mi' } },
        },
      ],
    },
  };
  patch(pod);
  return pod;
}

/** Namespaces that satisfy NOIP-NS-001 (PSA enforce=restricted) so other checks can be tested in isolation. */
export const ns = (...names: string[]): V1Namespace[] =>
  names.map((name) => ({ metadata: { name, labels: { 'pod-security.kubernetes.io/enforce': 'restricted' } } }));

/** Build a snapshot from the kind fixture YAMLs, exactly as the API would list them (minus server defaults). */
export function snapshotFromMisconfigFixtures(): ClusterSnapshot {
  const dir = new URL('./fixtures/misconfig/', import.meta.url);
  const docs = readdirSync(dir)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
    .flatMap((f) => parseAllDocuments(readFileSync(new URL(f, dir), 'utf8')).map((d) => d.toJS() as { kind: string }));
  const of = <T>(kind: string) => docs.filter((d) => d?.kind === kind) as unknown as T[];
  return snap({
    namespaces: of<V1Namespace>('Namespace'),
    pods: of<V1Pod>('Pod'),
    networkPolicies: of<V1NetworkPolicy>('NetworkPolicy'),
    clusterRoleBindings: of<V1ClusterRoleBinding>('ClusterRoleBinding'),
    roleBindings: of<V1RoleBinding>('RoleBinding'),
  });
}

export const golden = JSON.parse(readFileSync(new URL('./golden/kind-findings.json', import.meta.url), 'utf8')) as {
  scope: { namespacePrefix: string; clusterScopedNamePrefix: string };
  cleanNamespace: string;
  expectedFindingIds: string[];
  expectedFailedControls: string[];
  seededSecretValue: string;
};
