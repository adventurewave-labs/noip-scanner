import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/api/app.js';
import { labelValue, renderMetrics } from '../src/api/metrics.js';
import { K8sUnavailable } from '../src/errors.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const TOKEN = 'metrics-test-token-0123456789';
const auth = { Authorization: `Bearer ${TOKEN}` };
const demoSnap = async () => ({ snapshot: loadDemoSnapshot(), source: 'demo' as const });

/** Minimal parser for the exposition format: returns name{labels} -> value, and checks HELP/TYPE pairs. */
function parse(text: string): Map<string, number> {
  const m = new Map<string, number>();
  const typed = new Set<string>();
  for (const line of text.trim().split('\n')) {
    const t = /^# TYPE (\w+) (gauge|counter)$/.exec(line);
    if (t) typed.add(t[1]!);
    if (line.startsWith('#')) continue;
    const s = /^(\w+)(\{.*\})? (\S+)$/.exec(line);
    expect(s, line).not.toBeNull();
    expect(typed.has(s![1]!), `${s![1]} has a TYPE line`).toBe(true);
    m.set(`${s![1]}${s![2] ?? ''}`, Number(s![3]));
  }
  return m;
}

describe('renderMetrics', () => {
  it('exposes score, findings, failed checks, support days and Pod Security readiness', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-09-26T00:00:00Z') });
    const m = parse(renderMetrics(r, { up: true, durationSeconds: 0.25, failures: 0 }));
    expect(m.get('noip_up')).toBe(1);
    expect(m.get('noip_posture_score')).toBe(r.summary.score);
    expect(m.get('noip_findings{severity="critical"}')).toBe(r.summary.bySeverity.critical);
    expect(m.get('noip_check_failed{check="NOIP-POD-001",severity="critical"}')).toBe(1);
    expect(m.get('noip_scan_duration_seconds')).toBe(0.25);
    expect(m.get('noip_last_scan_timestamp_seconds')).toBe(Date.parse('2026-09-26T00:00:00Z') / 1000);
    expect(m.get('noip_kubernetes_support_days_left{minor="1.31"}')).toBeLessThan(0);
    expect(m.get('noip_namespace_pod_security_level{namespace="shop"}')).toBe(2);
    expect(m.get('noip_namespace_pod_security_level{namespace="ci"}')).toBe(0);
    // stable label sets: a passing check carries its severity too
    const failedPass = buildReport(loadDemoSnapshot(), 'demo', { excludeNamespaces: ['ci'] });
    const m2 = parse(renderMetrics(failedPass, { up: true, failures: 0 }));
    expect(m2.get('noip_check_failed{check="NOIP-POD-001",severity="critical"}')).toBe(0);
  });

  it('reports a failed scan without data, and escapes label values', () => {
    const down = parse(renderMetrics(undefined, { up: false, failures: 3 }));
    expect(down.get('noip_up')).toBe(0);
    expect(down.get('noip_scan_failures_total')).toBe(3);
    expect(labelValue('a"b\\c\nd')).toBe('a\\"b\\\\c\\nd');
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.provenance.cluster.context = 'x"}\n evil 1';
    const text = renderMetrics(r, { up: true, failures: 0 });
    expect(text).toContain('context="x\\"}\\n evil 1"');
    parse(text);
  });
});

describe('GET /api/metrics', () => {
  it('requires the bearer token and serves the exposition content type', async () => {
    const app = createApp({ token: TOKEN, demo: true });
    expect((await request(app).get('/api/metrics')).status).toBe(401);
    const res = await request(app).get('/api/metrics').set(auth);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/^text\/plain;(?=.*version=0\.0\.4)(?=.*charset=utf-8)/);
    expect(parse(res.text).get('noip_up')).toBe(1);
  });

  it('caches the scan for the TTL, shares one in-flight scan, and backs off after failures', async () => {
    let t = 1_000_000;
    let fail = false;
    const snapshot = vi.fn(async () => {
      if (fail) throw new K8sUnavailable('down');
      return demoSnap();
    });
    const app = createApp({ token: TOKEN, demo: false, snapshot, metricsTtlSeconds: 60, now: () => t });
    const both = await Promise.all([request(app).get('/api/metrics').set(auth), request(app).get('/api/metrics').set(auth)]);
    expect(snapshot).toHaveBeenCalledTimes(1); // concurrent scrapes share the scan…
    for (const r of both) expect(parse(r.text).get('noip_up')).toBe(1); // …and both wait for it (no spurious "down")
    t += 59_000;
    await request(app).get('/api/metrics').set(auth);
    expect(snapshot).toHaveBeenCalledTimes(1); // still fresh
    t += 2_000;
    fail = true;
    const down = parse((await request(app).get('/api/metrics').set(auth)).text);
    expect(snapshot).toHaveBeenCalledTimes(2);
    expect(down.get('noip_up')).toBe(0);
    expect(down.get('noip_scan_failures_total')).toBe(1);
    expect(down.has('noip_posture_score')).toBe(true); // last good values kept
    t += 10_000;
    await request(app).get('/api/metrics').set(auth);
    expect(snapshot).toHaveBeenCalledTimes(2); // retry backoff (30s)
    t += 30_000;
    fail = false;
    const up = parse((await request(app).get('/api/metrics').set(auth)).text);
    expect(snapshot).toHaveBeenCalledTimes(3);
    expect(up.get('noip_up')).toBe(1);
  });

  it('makes a scrape during a slow first scan wait, and backs off from the end of a slow failure', async () => {
    let t = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const snapshot = async () => {
      calls++;
      await gate;
      t += 45_000; // a 45 s API timeout
      throw new K8sUnavailable('timeout');
    };
    const app = createApp({ token: TOKEN, demo: false, snapshot, now: () => t });
    const a = request(app).get('/api/metrics').set(auth).then((r) => r.text);
    await new Promise((r) => setTimeout(r, 20));
    const b = request(app).get('/api/metrics').set(auth).then((r) => r.text);
    await new Promise((r) => setTimeout(r, 20));
    release();
    await Promise.all([a, b]);
    expect(calls).toBe(1);
    t += 1_000;
    await request(app).get('/api/metrics').set(auth);
    expect(calls).toBe(1); // backoff counted from when the 45 s attempt ended
  });

  it('labels non-Kubernetes failures generically', async () => {
    const app = createApp({ token: TOKEN, demo: false, snapshot: async () => { throw new Error('boom'); } });
    expect(parse((await request(app).get('/api/metrics').set(auth)).text).get('noip_up')).toBe(0);
  });
});
