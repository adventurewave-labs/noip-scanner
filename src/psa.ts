import type { V1Container, V1ObjectMeta, V1Pod, V1PodSpec } from '@kubernetes/client-node';

/**
 * Pod Security Standards evaluation: a port of the upstream Pod Security Admission checks
 * (github.com/kubernetes/pod-security-admission, policy/check_*.go; Apache-2.0), version-aware.
 * Conformance: test/psa.test.ts runs the upstream pass/fail fixtures for several versions.
 *
 * This is not one of NOIP's 15 checks and never affects the score. It answers a planning question:
 * "which Pod Security level could each namespace enforce today without rejecting its current pods?"
 */
export type PsaLevel = 'privileged' | 'baseline' | 'restricted';
/** Newest policy version implemented; later cluster versions are evaluated with it (PSA's `latest`). */
export const PSA_LATEST_MINOR = 37;
/** Oldest policy version evaluated; older clusters are evaluated with it (they are long past end of life). */
export const PSA_OLDEST_MINOR = 23;

interface PsaCheck {
  id: string;
  level: 'baseline' | 'restricted';
  /** First Kubernetes 1.x minor where the check exists. */
  since: number;
  /** Baseline checks this one replaces at the restricted level (from this check's `since` onwards). */
  overrides?: string[];
  /** Returns a violation description, or null when allowed. */
  run(meta: V1ObjectMeta, spec: V1PodSpec, minor: number): string | null;
}

type AnyContainer = V1Container;
const containers = (s: V1PodSpec): AnyContainer[] => [...(s.initContainers ?? []), ...(s.containers ?? []), ...((s.ephemeralContainers ?? []) as AnyContainer[])];
const names = (cs: AnyContainer[]) => cs.map((c) => c.name).join(', ');
const isWindows = (s: V1PodSpec) => s.os?.name === 'windows';
/** Pods with `hostUsers: false` run in a user namespace; some restricted checks relax for them from 1.35. */
const userNamespace = (s: V1PodSpec) => s.hostUsers === false;
const bad = (cond: boolean, msg: string) => (cond ? msg : null);

const CAPS_BASELINE = new Set(['AUDIT_WRITE', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'MKNOD', 'NET_BIND_SERVICE', 'SETFCAP', 'SETGID', 'SETPCAP', 'SETUID', 'SYS_CHROOT']);
const SYSCTLS: Array<[number, string[]]> = [
  [0, ['kernel.shm_rmid_forced', 'net.ipv4.ip_local_port_range', 'net.ipv4.tcp_syncookies', 'net.ipv4.ping_group_range', 'net.ipv4.ip_unprivileged_port_start']],
  [27, ['net.ipv4.ip_local_reserved_ports']],
  [29, ['net.ipv4.tcp_keepalive_time', 'net.ipv4.tcp_fin_timeout', 'net.ipv4.tcp_keepalive_intvl', 'net.ipv4.tcp_keepalive_probes']],
  [32, ['net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem']],
  [37, ['net.ipv4.tcp_slow_start_after_idle', 'net.ipv4.tcp_notsent_lowat']],
];
const SELINUX_TYPES = (minor: number) => new Set(['', 'container_t', 'container_init_t', 'container_kvm_t', ...(minor >= 31 ? ['container_engine_t'] : [])]);
const SAFE_VOLUMES = ['configMap', 'csi', 'downwardAPI', 'emptyDir', 'ephemeral', 'image', 'persistentVolumeClaim', 'projected', 'secret'];
const validSeccomp = (t?: string) => t === 'RuntimeDefault' || t === 'Localhost';
const validAppArmorType = (t?: string) => t === 'RuntimeDefault' || t === 'Localhost';
const validAppArmorAnnotation = (v: string) => v === '' || v === 'runtime/default' || v.startsWith('localhost/');

type Handler = { httpGet?: { host?: string }; tcpSocket?: { host?: string } } | undefined;
const hostSet = (h: Handler) => Boolean(h?.httpGet?.host || h?.tcpSocket?.host);

const procMount = (spec: V1PodSpec) => {
  const offenders = containers(spec).filter((c) => c.securityContext?.procMount !== undefined && c.securityContext.procMount !== 'Default');
  return bad(offenders.length > 0, `securityContext.procMount must be Default (${names(offenders)})`);
};

export const PSA_CHECKS: PsaCheck[] = [
  // ---- baseline ----
  {
    id: 'hostProcess',
    level: 'baseline',
    since: 0,
    run: (_m, s) =>
      bad(s.securityContext?.windowsOptions?.hostProcess === true || containers(s).some((c) => c.securityContext?.windowsOptions?.hostProcess === true), 'windowsOptions.hostProcess=true'),
  },
  {
    id: 'hostNamespaces',
    level: 'baseline',
    since: 0,
    run: (_m, s) => {
      const on = (['hostNetwork', 'hostPID', 'hostIPC'] as const).filter((k) => s[k] === true);
      return bad(on.length > 0, `${on.join(', ')}=true`);
    },
  },
  {
    id: 'privileged',
    level: 'baseline',
    since: 0,
    run: (_m, s) => {
      const o = containers(s).filter((c) => c.securityContext?.privileged === true);
      return bad(o.length > 0, `privileged containers (${names(o)})`);
    },
  },
  {
    id: 'capabilities_baseline',
    level: 'baseline',
    since: 0,
    run: (_m, s) => {
      const o = containers(s).filter((c) => (c.securityContext?.capabilities?.add ?? []).some((x) => !CAPS_BASELINE.has(x)));
      return bad(o.length > 0, `capabilities.add beyond the default set (${names(o)})`);
    },
  },
  {
    id: 'hostPathVolumes',
    level: 'baseline',
    since: 0,
    run: (_m, s) => {
      const v = (s.volumes ?? []).filter((x) => x.hostPath);
      return bad(v.length > 0, `hostPath volumes (${v.map((x) => x.name).join(', ')})`);
    },
  },
  {
    id: 'hostPorts',
    level: 'baseline',
    since: 0,
    run: (_m, s) => {
      const o = containers(s).filter((c) => (c.ports ?? []).some((p) => p.hostPort !== undefined && p.hostPort !== 0));
      return bad(o.length > 0, `hostPort set (${names(o)})`);
    },
  },
  {
    id: 'hostProbesAndHostLifecycle',
    level: 'baseline',
    since: 34,
    run: (_m, s) => {
      const o = containers(s).filter(
        (c) =>
          hostSet(c.livenessProbe as Handler) ||
          hostSet(c.readinessProbe as Handler) ||
          hostSet(c.startupProbe as Handler) ||
          hostSet(c.lifecycle?.postStart as Handler) ||
          hostSet(c.lifecycle?.preStop as Handler),
      );
      return bad(o.length > 0, `probe or lifecycle handler sets host (${names(o)})`);
    },
  },
  {
    id: 'appArmorProfile',
    level: 'baseline',
    since: 0,
    run: (m, s) => {
      const typed = [s.securityContext?.appArmorProfile, ...containers(s).map((c) => c.securityContext?.appArmorProfile)].filter((p) => p && !validAppArmorType(p.type));
      const annotations = Object.entries(m.annotations ?? {}).filter(([k, v]) => k.startsWith('container.apparmor.security.beta.kubernetes.io/') && !validAppArmorAnnotation(v));
      return bad(typed.length + annotations.length > 0, 'AppArmor profile other than RuntimeDefault or Localhost');
    },
  },
  {
    id: 'seLinuxOptions',
    level: 'baseline',
    since: 0,
    run: (_m, s, minor) => {
      const allowed = SELINUX_TYPES(minor);
      const opts = [s.securityContext?.seLinuxOptions, ...containers(s).map((c) => c.securityContext?.seLinuxOptions)];
      return bad(
        opts.some((o) => o && (!allowed.has(o.type ?? '') || Boolean(o.user) || Boolean(o.role))),
        'seLinuxOptions sets a disallowed type, or a user or role',
      );
    },
  },
  {
    id: 'procMount',
    level: 'baseline',
    since: 0,
    run: (_m, s, minor) => (minor >= 35 && userNamespace(s) ? null : procMount(s)),
  },
  {
    id: 'seccompProfile_baseline',
    level: 'baseline',
    since: 0,
    // Pre-1.19 annotation form omitted: evaluation starts at PSA_OLDEST_MINOR.
    run: (_m, s) => {
      const profiles = [s.securityContext?.seccompProfile, ...containers(s).map((c) => c.securityContext?.seccompProfile)];
      return bad(profiles.some((p) => p && !validSeccomp(p.type)), 'seccompProfile.type Unconfined');
    },
  },
  {
    id: 'sysctls',
    level: 'baseline',
    since: 0,
    run: (_m, s, minor) => {
      const allowed = new Set(SYSCTLS.filter(([v]) => v <= minor).flatMap(([, l]) => l));
      const o = (s.securityContext?.sysctls ?? []).filter((x) => !allowed.has(x.name));
      return bad(o.length > 0, `unsafe sysctls (${o.map((x) => x.name).join(', ')})`);
    },
  },
  // ---- restricted ----
  {
    id: 'restrictedVolumes',
    level: 'restricted',
    since: 0,
    overrides: ['hostPathVolumes'],
    run: (_m, s) => {
      // A volume with no source is defaulted to emptyDir by the API server, as upstream's fixtures assume.
      const v = (s.volumes ?? []).filter((x) => {
        const vol = x as unknown as Record<string, unknown>;
        const sources = Object.keys(vol).filter((k) => k !== 'name' && vol[k] != null);
        return sources.length > 0 && !SAFE_VOLUMES.some((k) => vol[k] != null);
      });
      return bad(v.length > 0, `volume types other than ${SAFE_VOLUMES.join('/')} (${v.map((x) => x.name).join(', ')})`);
    },
  },
  {
    id: 'allowPrivilegeEscalation',
    level: 'restricted',
    since: 8,
    run: (_m, s, minor) => {
      if (minor >= 25 && isWindows(s)) return null;
      const o = containers(s).filter((c) => c.securityContext?.allowPrivilegeEscalation !== false);
      return bad(o.length > 0, `allowPrivilegeEscalation must be false (${names(o)})`);
    },
  },
  {
    id: 'runAsNonRoot',
    level: 'restricted',
    since: 0,
    run: (_m, s, minor) => {
      if (minor >= 35 && userNamespace(s)) return null;
      const pod = s.securityContext?.runAsNonRoot;
      if (pod === false) return 'pod sets runAsNonRoot=false';
      const explicit = containers(s).filter((c) => c.securityContext?.runAsNonRoot === false);
      if (explicit.length) return `runAsNonRoot=false (${names(explicit)})`;
      const implicit = pod === true ? [] : containers(s).filter((c) => c.securityContext?.runAsNonRoot === undefined);
      return bad(implicit.length > 0, `pod or containers must set runAsNonRoot=true (${names(implicit)})`);
    },
  },
  {
    id: 'runAsUser',
    level: 'restricted',
    since: 23,
    run: (_m, s, minor) => {
      if (minor >= 35 && userNamespace(s)) return null;
      return bad(s.securityContext?.runAsUser === 0 || containers(s).some((c) => c.securityContext?.runAsUser === 0), 'runAsUser=0');
    },
  },
  {
    id: 'seccompProfile_restricted',
    level: 'restricted',
    since: 19,
    overrides: ['seccompProfile_baseline'],
    run: (_m, s, minor) => {
      if (minor >= 25 && isWindows(s)) return null;
      const pod = s.securityContext?.seccompProfile;
      if (pod && !validSeccomp(pod.type)) return 'pod seccompProfile.type Unconfined';
      const cs = containers(s);
      if (cs.some((c) => c.securityContext?.seccompProfile && !validSeccomp(c.securityContext.seccompProfile.type))) return 'container seccompProfile.type Unconfined';
      const implicit = pod ? [] : cs.filter((c) => !c.securityContext?.seccompProfile);
      return bad(implicit.length > 0, `pod or containers must set seccompProfile RuntimeDefault or Localhost (${names(implicit)})`);
    },
  },
  {
    id: 'capabilities_restricted',
    level: 'restricted',
    since: 22,
    overrides: ['capabilities_baseline'],
    run: (_m, s, minor) => {
      if (minor >= 25 && isWindows(s)) return null;
      const noDrop = containers(s).filter((c) => !(c.securityContext?.capabilities?.drop ?? []).includes('ALL'));
      const added = containers(s).filter((c) => (c.securityContext?.capabilities?.add ?? []).some((x) => x !== 'NET_BIND_SERVICE'));
      if (noDrop.length) return `capabilities.drop must include ALL (${names(noDrop)})`;
      return bad(added.length > 0, `capabilities.add may only contain NET_BIND_SERVICE (${names(added)})`);
    },
  },
  {
    id: 'procMount_restricted',
    level: 'restricted',
    since: 35,
    overrides: ['procMount'],
    run: (_m, s) => procMount(s),
  },
];

export interface PodPsa {
  /** Highest level the pod satisfies. */
  level: PsaLevel;
  /** Violations that keep it below baseline, then below restricted. */
  baseline: string[];
  restricted: string[];
}

/** Drop null values, as the API server does when it decodes an object (Go nil / zero value). YAML `key:` means null. */
export function stripNulls<T>(v: T, keepArrayPositions = false): T {
  if (Array.isArray(v)) return (keepArrayPositions ? v : v.filter((x) => x != null)).map((x) => stripNulls(x, keepArrayPositions)) as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => x != null).map(([k, x]) => [k, stripNulls(x, keepArrayPositions)])) as T;
  return v;
}

export function evaluatePod(pod: Pick<V1Pod, 'metadata' | 'spec'>, minor = PSA_LATEST_MINOR): PodPsa {
  const m = Math.max(PSA_OLDEST_MINOR, Math.min(minor, PSA_LATEST_MINOR));
  const meta = stripNulls(pod.metadata ?? {});
  const spec = stripNulls(pod.spec ?? { containers: [] });
  const active = PSA_CHECKS.filter((c) => c.since <= m);
  const overridden = new Set(active.filter((c) => c.level === 'restricted').flatMap((c) => c.overrides ?? []));
  const violations = (cs: PsaCheck[]) => cs.flatMap((c) => c.run(meta, spec, m) ?? []).map(String);
  const baseline = violations(active.filter((c) => c.level === 'baseline'));
  // At the restricted level, the non-overridden baseline checks still apply alongside the restricted ones.
  const restrictedAll = violations(active.filter((c) => c.level === 'restricted' || !overridden.has(c.id)));
  const level: PsaLevel = baseline.length ? 'privileged' : restrictedAll.length ? 'baseline' : 'restricted';
  return { level, baseline, restricted: restrictedAll.filter((v) => !baseline.includes(v)) };
}

// ---------- namespace readiness ----------

export interface NamespaceReadiness {
  namespace: string;
  /** Current `pod-security.kubernetes.io/enforce` label, if any. */
  enforce?: string;
  pods: number;
  /** Highest level every current pod satisfies: enforcing it rejects none of today's workloads. */
  canEnforce: PsaLevel;
  /** Workloads that keep the namespace below the next level, with the reasons. */
  blockers: Array<{ resource: string; level: 'baseline' | 'restricted'; reasons: string[] }>;
}

export interface PodSecurityReadiness {
  /** Pod Security policy version evaluated, e.g. "1.37" (the cluster's minor, capped at the newest implemented). */
  policyVersion: string;
  namespaces: NamespaceReadiness[];
}

const RANK: Record<PsaLevel, number> = { privileged: 0, baseline: 1, restricted: 2 };

/** Pure: per-namespace readiness from the pods in a snapshot. `workloadKey` collapses replicas into one blocker. */
export function podSecurityReadiness(
  pods: V1Pod[],
  namespaces: Array<{ metadata?: V1ObjectMeta }>,
  excluded: ReadonlySet<string>,
  workloadKey: (p: V1Pod) => string,
  minor = PSA_LATEST_MINOR,
): PodSecurityReadiness {
  const m = Math.max(PSA_OLDEST_MINOR, Math.min(minor, PSA_LATEST_MINOR));
  const byNs = new Map<string, V1Pod[]>();
  for (const n of namespaces) if (n.metadata?.name && !excluded.has(n.metadata.name)) byNs.set(n.metadata.name, []);
  for (const p of pods) {
    const ns = p.metadata?.namespace ?? 'default';
    if (excluded.has(ns)) continue;
    byNs.set(ns, [...(byNs.get(ns) ?? []), p]);
  }
  const labels = new Map(namespaces.map((n) => [n.metadata?.name, n.metadata?.labels?.['pod-security.kubernetes.io/enforce']]));
  const out = [...byNs.entries()].map(([namespace, list]) => {
    const evals = list.map((p) => ({ p, e: evaluatePod(p, m) }));
    const canEnforce = evals.reduce<PsaLevel>((lvl, { e }) => (RANK[e.level] < RANK[lvl] ? e.level : lvl), 'restricted');
    const blockers = new Map<string, NamespaceReadiness['blockers'][number]>();
    if (canEnforce !== 'restricted') {
      const next = canEnforce === 'privileged' ? 'baseline' : 'restricted';
      for (const { p, e } of evals) {
        const reasons = next === 'baseline' ? e.baseline : e.restricted;
        const key = workloadKey(p);
        if (reasons.length && !blockers.has(key)) blockers.set(key, { resource: key, level: next, reasons });
      }
    }
    const enforce = labels.get(namespace);
    return { namespace, ...(enforce ? { enforce } : {}), pods: list.length, canEnforce, blockers: [...blockers.values()].sort((a, b) => a.resource.localeCompare(b.resource)) };
  });
  return { policyVersion: `1.${m}`, namespaces: out.sort((a, b) => a.namespace.localeCompare(b.namespace)) };
}
