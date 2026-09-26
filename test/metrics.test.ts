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
    const m = parse(renderMetrics(r, { up: true, durationSeconds: 0.25 }));
    expect(m.get('noip_up')).toBe(1);
    expect(m.get('noip_posture_score')).toBe(r.summary.score);
    expect(m.get('noip_findings{severity="critical"}')).toBe(r.summary.bySeverity.critical);
    expect(m.get('noip_check_failed{check="NOIP-POD-001",severity="critical"}')).toBe(1);
    expect(m.get('noip_scan_duration_seconds')).toBe(0.25);
    expect(m.get('noip_last_scan_timestamp_seconds')).toBe(Date.parse('2026-09-26T00:00:00Z') / 1000);
    expect(m.get('noip_kubernetes_support_days_left{minor="1.31"}')).toBeLessThan(0);
    expect(m.get('noip_namespace_pod_security_level{namespace="shop"}')).toBe(2);
    expect(m.get('noip_namespace_pod_security_level{namespace="ci"}')).toBe(0);
    const passing = r.provenance.checksRun.find((c) => !r.findings.some((f) => f.checkId === c));
    if (passing) expect(m.get(`noip_check_failed{check="${passing}"}`)).toBe(0);
  });

  it('reports a failed scan without data, and escapes label values', () => {
    expect(parse(renderMetrics(undefined, { up: false, lastError: 'K8sUnavailable' })).get('noip_up{error="K8sUnavailable"}')).toBe(0);
    expect(labelValue('a"b\\c\nd')).toBe('a\\"b\\\\c\\nd');
    const r = buildReport(loadDemoSnapshot(), 'demo');
    r.provenance.cluster.context = 'x"}\n evil 1';
    const text = renderMetrics(r, { up: true });
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
    await Promise.all([request(app).get('/api/metrics').set(auth), request(app).get('/api/metrics').set(auth)]);
    expect(snapshot).toHaveBeenCalledTimes(1); // concurrent scrapes share the scan
    t += 59_000;
    await request(app).get('/api/metrics').set(auth);
    expect(snapshot).toHaveBeenCalledTimes(1); // still fresh
    t += 2_000;
    fail = true;
    const down = parse((await request(app).get('/api/metrics').set(auth)).text);
    expect(snapshot).toHaveBeenCalledTimes(2);
    expect(down.get('noip_up{error="K8sUnavailable"}')).toBe(0);
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

  it('labels non-Kubernetes failures generically', async () => {
    const app = createApp({ token: TOKEN, demo: false, snapshot: async () => { throw new Error('boom'); } });
    expect(parse((await request(app).get('/api/metrics').set(auth)).text).get('noip_up{error="Error"}')).toBe(0);
  });
});
