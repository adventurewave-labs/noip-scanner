import type { V1Container, V1Pod } from '@kubernetes/client-node';
import type { ClusterSnapshot } from '../types.js';
import type { Check, CheckContext, RawFinding } from './types.js';
import { containersOf, inScope, workloadOf } from './workload.js';

type ContainerTest = (c: V1Container, pod: V1Pod, path: string) => string | null;
type PodTest = (pod: V1Pod) => string | null;

function perContainer(test: ContainerTest) {
  return (snap: ClusterSnapshot, ctx: CheckContext): RawFinding[] => {
    const out: RawFinding[] = [];
    for (const pod of snap.pods) {
      if (!inScope(pod.metadata?.namespace, ctx.excludedNamespaces)) continue;
      const wl = workloadOf(pod);
      for (const { container, path } of containersOf(pod)) {
        const evidence = test(container, pod, path);
        if (evidence) out.push({ resource: { ...wl, container: container.name }, evidence });
      }
    }
    return out;
  };
}

function perPod(test: PodTest) {
  return (snap: ClusterSnapshot, ctx: CheckContext): RawFinding[] => {
    const out: RawFinding[] = [];
    for (const pod of snap.pods) {
      if (!inScope(pod.metadata?.namespace, ctx.excludedNamespaces)) continue;
      const evidence = test(pod);
      if (evidence) out.push({ resource: workloadOf(pod), evidence });
    }
    return out;
  };
}

export const podChecks: Check[] = [
  {
    id: 'NOIP-POD-001',
    title: 'Privileged container',
    severity: 'critical',
    category: 'Pod Security',
    controls: ['CIS-5.2.1'],
    remediation: 'Remove securityContext.privileged: true; grant only the specific Linux capabilities required.',
    run: perContainer((c, _p, path) =>
      c.securityContext?.privileged === true ? `${path}.securityContext.privileged=true` : null,
    ),
  },
  {
    id: 'NOIP-POD-002',
    title: 'Pod shares the host PID namespace',
    severity: 'critical',
    category: 'Pod Security',
    controls: ['CIS-5.2.2'],
    remediation: 'Remove hostPID: true from the pod spec.',
    run: perPod((p) => (p.spec?.hostPID === true ? 'spec.hostPID=true' : null)),
  },
  {
    id: 'NOIP-POD-003',
    title: 'Pod shares the host IPC namespace',
    severity: 'high',
    category: 'Pod Security',
    controls: ['CIS-5.2.3'],
    remediation: 'Remove hostIPC: true from the pod spec.',
    run: perPod((p) => (p.spec?.hostIPC === true ? 'spec.hostIPC=true' : null)),
  },
  {
    id: 'NOIP-POD-004',
    title: 'Pod uses the host network',
    severity: 'high',
    category: 'Pod Security',
    controls: ['CIS-5.2.4'],
    remediation: 'Remove hostNetwork: true unless the workload is a node-level agent that genuinely needs it.',
    run: perPod((p) => (p.spec?.hostNetwork === true ? 'spec.hostNetwork=true' : null)),
  },
  {
    id: 'NOIP-POD-005',
    title: 'Privilege escalation not disabled',
    severity: 'medium',
    category: 'Pod Security',
    controls: ['CIS-5.2.5'],
    remediation: 'Set securityContext.allowPrivilegeEscalation: false on every container.',
    run: perContainer((c, _p, path) => {
      const v = c.securityContext?.allowPrivilegeEscalation;
      return v === false ? null : `${path}.securityContext.allowPrivilegeEscalation=${v === undefined ? 'unset' : String(v)}`;
    }),
  },
  {
    id: 'NOIP-POD-006',
    title: 'Container may run as root',
    severity: 'high',
    category: 'Pod Security',
    controls: ['CIS-5.2.6'],
    remediation: 'Set runAsNonRoot: true (pod or container securityContext) and a non-zero runAsUser.',
    run: perContainer((c, pod, path) => {
      const podSc = pod.spec?.securityContext;
      const user = c.securityContext?.runAsUser ?? podSc?.runAsUser;
      const nonRoot = c.securityContext?.runAsNonRoot ?? podSc?.runAsNonRoot;
      if (user === 0) return `${path}: effective runAsUser=0`;
      if (nonRoot === true || (user !== undefined && user > 0)) return null;
      if (nonRoot === false) return `${path}: effective runAsNonRoot=false and no non-zero runAsUser`;
      return `${path}: runAsNonRoot and runAsUser unset at pod and container level`;
    }),
  },
  {
    id: 'NOIP-POD-007',
    title: 'Writable root filesystem',
    severity: 'medium',
    category: 'Pod Security',
    controls: [],
    remediation: 'Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for writable paths.',
    run: perContainer((c, _p, path) =>
      c.securityContext?.readOnlyRootFilesystem === true
        ? null
        : `${path}.securityContext.readOnlyRootFilesystem=${String(c.securityContext?.readOnlyRootFilesystem ?? 'unset')}`,
    ),
  },
  {
    id: 'NOIP-POD-008',
    title: 'Missing CPU or memory limit',
    severity: 'low',
    category: 'Pod Security',
    controls: [],
    remediation: 'Define resources.limits.cpu and resources.limits.memory.',
    run: perContainer((c, _p, path) => {
      // The API rejects resources on ephemeral containers, so a finding there could never be fixed.
      if (path.startsWith('spec.ephemeralContainers')) return null;
      const missing = (['cpu', 'memory'] as const).filter((k) => !c.resources?.limits?.[k]);
      return missing.length ? `${path}.resources.limits missing ${missing.join(', ')}` : null;
    }),
  },
  {
    id: 'NOIP-POD-009',
    title: 'Secret exposed as environment variable',
    severity: 'medium',
    category: 'Secrets',
    controls: ['CIS-5.4.1'],
    remediation: 'Mount the secret as a read-only volume instead of env.valueFrom.secretKeyRef / envFrom.secretRef.',
    run: perContainer((c, _p, path) => {
      // Names and keys only — the scanner has no secrets access and never sees values.
      const refs: string[] = [];
      for (const e of c.env ?? []) {
        const r = e.valueFrom?.secretKeyRef;
        if (r) refs.push(`env[${e.name}] <- secret ${r.name}/${r.key}`);
      }
      for (const e of c.envFrom ?? []) {
        if (e.secretRef) refs.push(`envFrom <- secret ${e.secretRef.name}`);
      }
      return refs.length ? `${path}: ${refs.join('; ')}` : null;
    }),
  },
];
