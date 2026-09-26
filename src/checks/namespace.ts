import type { Check } from './types.js';

const ENFORCE = 'pod-security.kubernetes.io/enforce';

export const namespaceChecks: Check[] = [
  {
    id: 'NOIP-NS-001',
    title: 'Pod Security Admission not enforcing baseline or restricted',
    severity: 'medium',
    category: 'Pod Security',
    // Built-in admission control (Kubernetes >= 1.25) that blocks non-compliant pods at creation time;
    // the pod checks above only detect what is already running.
    controls: [],
    remediation: `Label the namespace ${ENFORCE}=restricted (or baseline where restricted is not yet feasible), after a dry run with pod-security.kubernetes.io/warn.`,
    run: (snap, ctx) =>
      snap.namespaces
        .filter((n) => n.metadata?.name && !ctx.excludedNamespaces.has(n.metadata.name))
        .flatMap((n) => {
          const level = n.metadata?.labels?.[ENFORCE];
          if (level === 'baseline' || level === 'restricted') return [];
          return [
            {
              resource: { kind: 'Namespace', name: n.metadata!.name! },
              evidence: level ? `metadata.labels["${ENFORCE}"]=${level}` : `metadata.labels["${ENFORCE}"] unset (no admission-time pod security)`,
            },
          ];
        }),
  },
];
