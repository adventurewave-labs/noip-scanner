import type { Check } from './types.js';

const ANY_CIDR = new Set(['0.0.0.0/0', '::/0']);

export const networkChecks: Check[] = [
  {
    id: 'NOIP-NET-001',
    title: 'Namespace has no NetworkPolicy',
    severity: 'high',
    category: 'Network',
    controls: ['CIS-5.3.2'],
    remediation: 'Add a default-deny NetworkPolicy (ingress and egress) plus explicit allow rules.',
    run: (snap, ctx) => {
      const covered = new Set(snap.networkPolicies.map((p) => p.metadata?.namespace).filter(Boolean));
      return snap.namespaces
        .map((n) => n.metadata?.name ?? '')
        .filter((name) => name && !ctx.excludedNamespaces.has(name) && !covered.has(name))
        .map((name) => ({
          resource: { kind: 'Namespace', name },
          evidence: `0 NetworkPolicy objects in namespace ${name}`,
        }));
    },
  },
  {
    id: 'NOIP-NET-002',
    title: 'NetworkPolicy allows egress to any destination',
    severity: 'medium',
    category: 'Network',
    controls: [],
    remediation: 'Give every egress rule an explicit `to` (namespaceSelector/podSelector/ipBlock) and ports.',
    run: (snap, ctx) =>
      snap.networkPolicies
        .filter((p) => !ctx.excludedNamespaces.has(p.metadata?.namespace ?? 'default'))
        .flatMap((p) => {
          const egress = p.spec?.egress ?? [];
          const open = egress.findIndex((r) => !r.to || r.to.length === 0);
          const anyIp = egress.findIndex((r) => (r.to ?? []).some((t) => ANY_CIDR.has(t.ipBlock?.cidr ?? '') && !t.ipBlock?.except?.length));
          const idx = open >= 0 ? open : anyIp;
          if (idx < 0) return [];
          return [
            {
              resource: { kind: 'NetworkPolicy', namespace: p.metadata?.namespace ?? 'default', name: p.metadata?.name ?? 'unknown' },
              evidence:
                idx === open
                  ? `spec.egress[${idx}] has no 'to' selector (all destinations allowed)`
                  : `spec.egress[${idx}] allows ipBlock ${egress[idx]!.to!.find((t) => ANY_CIDR.has(t.ipBlock?.cidr ?? ''))!.ipBlock!.cidr} with no exceptions`,
            },
          ];
        }),
  },
];
