import { readFileSync } from 'node:fs';
import type { V1Container, V1Pod } from '@kubernetes/client-node';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsPlugin from 'ajv-formats';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { ManifestError, parseManifestText } from '../src/manifests.js';
import { redact, scrubString } from '../src/llm/redact.js';
import { diffReports } from '../src/report/diff.js';
import { buildReport } from '../src/scan.js';
import { applySuppressions, globToRegExp } from '../src/suppressions.js';
import { snap } from './helpers.js';

// Property-based tests: invariants that must hold for *any* input, not just hand-picked fixtures.
const RUNS = { numRuns: 150 };
const ajv = new Ajv2020({ allErrors: true, strict: true });
((addFormatsPlugin as unknown as { default?: unknown }).default as (a: Ajv2020) => void)(ajv);
const validate = ajv.compile(JSON.parse(readFileSync(new URL('../schemas/report.schema.json', import.meta.url), 'utf8')));

const dns = fc.stringMatching(/^[a-z][a-z0-9-]{0,14}$/);
const maybe = <T>(a: fc.Arbitrary<T>) => fc.option(a, { nil: undefined });
// `undefined` fields model absent fields: the checks treat both the same way.
const container = fc.record({
  name: dns,
  image: fc.constant('img'),
  securityContext: maybe(
    fc.record({
      privileged: maybe(fc.boolean()),
      allowPrivilegeEscalation: maybe(fc.boolean()),
      readOnlyRootFilesystem: maybe(fc.boolean()),
      runAsNonRoot: maybe(fc.boolean()),
      runAsUser: maybe(fc.integer({ min: 0, max: 70000 })),
    }),
  ),
  resources: maybe(fc.record({ limits: maybe(fc.record({ cpu: maybe(fc.constant('100m')), memory: maybe(fc.constant('64Mi')) })) })),
  env: maybe(fc.array(fc.record({ name: dns, valueFrom: maybe(fc.record({ secretKeyRef: fc.record({ name: dns, key: dns }) })) }), { maxLength: 2 })),
}) as unknown as fc.Arbitrary<V1Container>;
const pod = fc.record({
  metadata: fc.record({ name: dns, namespace: fc.constantFrom('a', 'b', 'kube-system') }),
  spec: fc.record({
    hostPID: maybe(fc.boolean()),
    hostIPC: maybe(fc.boolean()),
    hostNetwork: maybe(fc.boolean()),
    securityContext: maybe(fc.record({ runAsNonRoot: maybe(fc.boolean()), runAsUser: maybe(fc.integer({ min: 0, max: 70000 })) })),
    containers: fc.uniqueArray(container, { selector: (c) => c.name, minLength: 1, maxLength: 3 }),
  }),
}) as unknown as fc.Arbitrary<V1Pod>;
const snapshot = fc.record({ pods: fc.array(pod, { maxLength: 12 }), nsLabel: fc.constantFrom(undefined, 'restricted', 'privileged') }).map(({ pods, nsLabel }) =>
  snap({
    pods,
    namespaces: ['a', 'b', 'kube-system'].map((name) => ({ metadata: { name, labels: nsLabel ? { 'pod-security.kubernetes.io/enforce': nsLabel } : undefined } })),
    networkPolicies: [{ metadata: { name: 'np', namespace: 'a' }, spec: { podSelector: {}, egress: [{}] } }],
  }),
);
const NOW = new Date('2026-01-01T00:00:00Z');

describe('property: reports', () => {
  it('are always schema-valid, internally consistent and deterministic', () => {
    fc.assert(
      fc.property(snapshot, (s) => {
        const r = buildReport(s, 'live', { now: NOW });
        expect(validate(r)).toBe(true);
        expect(r.summary.findings).toBe(r.findings.length);
        expect(Object.values(r.summary.bySeverity).reduce((a, b) => a + b, 0)).toBe(r.findings.length);
        expect(new Set(r.findings.map((f) => f.id)).size).toBe(r.findings.length);
        for (const f of r.findings) expect(f.id.startsWith(`${f.checkId}:${f.resource.kind}/`)).toBe(true);
        const ids = new Set(r.findings.map((f) => f.id));
        for (const c of r.controls) for (const id of c.findingIds) expect(ids.has(id)).toBe(true);
        expect(r.summary.score).toBeGreaterThanOrEqual(0);
        expect(r.summary.score).toBeLessThanOrEqual(100);
        expect(JSON.stringify(buildReport(s, 'live', { now: NOW }))).toBe(JSON.stringify(r));
      }),
      RUNS,
    );
  });

  it('do not depend on the order the API returns pods in', () => {
    fc.assert(
      fc.property(snapshot, fc.infiniteStream(fc.nat()), (s, rnd) => {
        const shuffled = { ...s, pods: [...s.pods].sort(() => (rnd.next().value % 3) - 1) };
        const ids = (x: typeof s) => buildReport(x, 'live', { now: NOW }).findings.map((f) => f.id).sort();
        // Replicas of one workload may carry different evidence; the set of finding IDs must not change.
        expect(ids(shuffled)).toEqual(ids(s));
      }),
      RUNS,
    );
  });

  it('never report anything in excluded namespaces except cluster-scoped RBAC', () => {
    fc.assert(
      fc.property(snapshot, (s) => {
        for (const f of buildReport(s, 'live').findings) expect(f.resource.namespace === 'kube-system' || f.resource.name === 'kube-system').toBe(false);
      }),
      RUNS,
    );
  });

  it('diff of a report with itself is empty', () => {
    fc.assert(
      fc.property(snapshot, (s) => {
        const r = buildReport(s, 'live', { now: NOW });
        const d = diffReports(r, r);
        expect([d.new.length, d.resolved.length, d.changed.length, d.controls.length, d.scoreDelta]).toEqual([0, 0, 0, 0, 0]);
      }),
      RUNS,
    );
  });

  it('min-severity filtering never keeps a finding below the floor', () => {
    fc.assert(
      fc.property(snapshot, fc.constantFrom('critical', 'high', 'medium', 'low') as fc.Arbitrary<'critical' | 'high' | 'medium' | 'low'>, (s, floor) => {
        const order = ['critical', 'high', 'medium', 'low'];
        for (const f of buildReport(s, 'live', { minSeverity: floor }).findings) expect(order.indexOf(f.severity)).toBeLessThanOrEqual(order.indexOf(floor));
      }),
      RUNS,
    );
  });
});

describe('property: suppressions', () => {
  it('partition findings exactly (active + suppressed = all, no duplicates)', () => {
    const sup = fc.array(
      fc.record({
        check: fc.constantFrom('NOIP-POD-001', 'NOIP-POD-005', 'NOIP-NET-001', 'NOIP-POD-008'),
        resource: maybe(fc.constantFrom('Pod/a/**', 'Namespace/*', 'Pod/b/*/*')),
        reason: fc.constant('accepted for property test'),
        owner: fc.constant('o'),
        expires: fc.constantFrom('2000-01-01', '2099-01-01'),
      }),
      { maxLength: 5 },
    );
    fc.assert(
      fc.property(snapshot, sup, (s, sups) => {
        const all = buildReport(s, 'live').findings;
        const out = applySuppressions(all, sups, NOW);
        expect(out.active.length + out.suppressed.length).toBe(all.length);
        const seen = new Set([...out.active.map((f) => f.id), ...out.suppressed.map((x) => x.finding.id)]);
        expect(seen.size).toBe(all.length);
        for (const x of out.suppressed) expect(x.suppression.expires >= '2026-01-01').toBe(true);
      }),
      RUNS,
    );
  });

  it('a glob without wildcards matches exactly itself', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }).filter((x) => !x.includes('*')), fc.string({ maxLength: 40 }), (lit, other) => {
        const re = globToRegExp(lit);
        expect(re.test(lit)).toBe(true);
        if (other !== lit) expect(re.test(other)).toBe(false);
      }),
      RUNS,
    );
  });
});

describe('fuzz: redaction', () => {
  const secret = fc.stringMatching(/^[A-Za-z0-9]{12,40}$/);
  it('secret values under env/annotations/data/stringData/value keys never survive redact()', () => {
    const key = fc.constantFrom('env', 'annotations', 'data', 'stringData', 'value', 'token', 'password', 'secret');
    fc.assert(
      fc.property(secret, key, fc.array(dns, { maxLength: 3 }), (s, k, path) => {
        let obj: Record<string, unknown> = { [k]: { nested: s, list: [s] } };
        for (const p of path) obj = { [p]: obj, keep: 'visible' };
        expect(JSON.stringify(redact(obj))).not.toContain(s);
      }),
      RUNS,
    );
  });

  it('token-shaped strings are scrubbed wherever they appear in text', () => {
    const tokens = fc.oneof(
      fc.stringMatching(/^[A-Z0-9]{16}$/).map((x) => `AKIA${x}`),
      fc.stringMatching(/^[A-Za-z0-9]{24}$/).map((x) => `ghp_${x}`),
      fc.tuple(fc.stringMatching(/^[A-Za-z0-9_-]{10,20}$/), fc.stringMatching(/^[A-Za-z0-9_-]{10,20}$/), fc.stringMatching(/^[A-Za-z0-9_-]{10,20}$/)).map(([a, b, c]) => `eyJ${a}.${b}.${c}`),
      fc.stringMatching(/^[A-Za-z0-9]{20,30}$/).map((x) => `sk-${x}`),
    );
    fc.assert(
      fc.property(fc.string({ maxLength: 20 }), tokens, fc.string({ maxLength: 20 }), (pre, tok, post) => {
        expect(scrubString(`${pre} ${tok} ${post}`)).not.toContain(tok);
      }),
      RUNS,
    );
  });
});

describe('fuzz: manifest parser', () => {
  it('never crashes with anything but a ManifestError on arbitrary input', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 300 }), fc.jsonValue().map((v) => JSON.stringify(v))), (text) => {
        try {
          parseManifestText(text, 'fuzz.yaml');
        } catch (err) {
          expect(err).toBeInstanceOf(ManifestError);
        }
      }),
      { numRuns: 500 },
    );
  });
});
