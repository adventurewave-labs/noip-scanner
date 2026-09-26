import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp, type AppDeps } from '../src/api/app.js';
import { K8sUnavailable, LLMNotConfigured } from '../src/errors.js';
import { TextProvider } from '../src/llm/provider.js';
import { getSnapshot } from '../src/scan.js';

const TOKEN = 'test-token-0123456789abcdef';
const auth = { Authorization: `Bearer ${TOKEN}` };
const down = async () => {
  throw new K8sUnavailable('list pods failed: connect ECONNREFUSED');
};
const noLLM = async () => {
  throw new LLMNotConfigured();
};
const live = (over: Partial<AppDeps> = {}) => createApp({ token: TOKEN, demo: false, snapshot: down, probe: down, provider: noLLM, ...over });
const demo = (over: Partial<AppDeps> = {}) => createApp({ token: TOKEN, demo: true, provider: noLLM, ...over });

class Fake extends TextProvider {
  readonly name = 'fake';
  readonly model = 'fake';
  protected async completeText() {
    return '{"summary":"explained","priorities":[]}';
  }
}

describe('auth (R-5)', () => {
  it('rejects /api/* without or with a wrong token', async () => {
    await request(live()).get('/api/scan').expect(401);
    await request(live()).get('/api/scan').set('Authorization', 'Bearer nope').expect(401);
    await request(live()).post('/api/report/explain').expect(401);
  });
  it('leaves /health open', async () => {
    await request(live()).get('/health').expect(200);
  });
});

describe('no silent fixtures (R-3)', () => {
  it('returns 503 K8sUnavailable on /api/discovery/cluster and /api/scan when the cluster is unreachable', async () => {
    const r = await request(live()).get('/api/discovery/cluster').set(auth).expect(503);
    expect(r.body).toEqual({ error: 'K8sUnavailable', message: 'list pods failed: connect ECONNREFUSED' });
    await request(live()).get('/api/scan').set(auth).expect(503);
  });

  it('with no kubeconfig at all (real loader) returns 503', async () => {
    const prev = process.env.KUBECONFIG;
    process.env.KUBECONFIG = '/nonexistent/kubeconfig';
    try {
      const r = await request(createApp({ token: TOKEN, demo: false, snapshot: getSnapshot })).get('/api/discovery/cluster').set(auth).expect(503);
      expect(r.body.error).toBe('K8sUnavailable');
      const h = await request(createApp({ token: TOKEN, demo: false })).get('/health').expect(200);
      expect(h.body).toMatchObject({ status: 'degraded', kubernetes: 'unreachable' });
    } finally {
      if (prev === undefined) delete process.env.KUBECONFIG;
      else process.env.KUBECONFIG = prev;
    }
  });

  it('health reports degraded, not healthy, when Kubernetes is unreachable', async () => {
    const r = await request(live()).get('/health').expect(200);
    expect(r.body).toMatchObject({ status: 'degraded', source: 'live', kubernetes: 'unreachable', gitSha: 'test-sha' });
    expect(JSON.stringify(r.body)).not.toMatch(/Production[ ]Ready|capabilities/);
  });

  it('health is ok when the probe succeeds', async () => {
    const r = await request(live({ probe: async () => 'v1.31.0' })).get('/health').expect(200);
    expect(r.body).toMatchObject({ status: 'ok', kubernetes: 'reachable', serverVersion: 'v1.31.0' });
  });

  it('demo mode returns 200 with source "demo" and labels itself', async () => {
    const d = await request(demo()).get('/api/discovery/cluster').set(auth).expect(200);
    expect(d.body).toMatchObject({ source: 'demo', serverVersion: 'v1.31.4', nodeCount: 3 });
    expect(d.headers['x-noip-mode']).toBe('demo');
    const s = await request(demo()).get('/api/scan').set(auth).expect(200);
    expect(s.body.source).toBe('demo');
    expect(s.body.findings.length).toBeGreaterThan(0);
    const h = await request(demo()).get('/health').expect(200);
    expect(h.body).toMatchObject({ status: 'ok', source: 'demo' });
  });

  it('includeSystem=1 widens the scan', async () => {
    const narrow = await request(demo()).get('/api/scan').set(auth);
    const wide = await request(demo()).get('/api/scan?includeSystem=1').set(auth);
    expect(wide.body.findings.length).toBeGreaterThan(narrow.body.findings.length);
  });
});

describe('explain endpoint (R-6)', () => {
  it('returns 501 when no LLM key is configured, and the scan still works', async () => {
    const r = await request(demo()).post('/api/report/explain').set(auth).expect(501);
    expect(r.body.error).toBe('LLMNotConfigured');
    await request(demo()).get('/api/scan').set(auth).expect(200);
  });
  it('returns the deterministic report plus an explanation with a configured provider', async () => {
    const r = await request(demo({ provider: async () => new Fake() })).post('/api/report/explain').set(auth).expect(200);
    expect(r.body.explanation).toEqual({ summary: 'explained', priorities: [], caveats: [] });
    expect(r.body.findings.length).toBeGreaterThan(0);
  });
});

describe('misc routes', () => {
  it('404s unknown paths (Express 5 catch-all)', async () => {
    const r = await request(live()).get('/nope').expect(404);
    expect(r.body.error).toBe('NotFound');
  });
  it('serves a demo banner page at / in demo mode and JSON otherwise', async () => {
    const d = await request(demo()).get('/').expect(200);
    expect(d.text).toContain('DEMO MODE');
    expect(d.text).not.toContain('<script');
    const l = await request(live()).get('/').expect(200);
    expect(l.body.name).toBe('noip');
  });
  it('maps unexpected errors to 500 without leaking details', async () => {
    const r = await request(live({ snapshot: async () => { throw new Error('secret internals'); } })).get('/api/scan').set(auth).expect(500);
    expect(r.body).toEqual({ error: 'Internal', message: 'Internal server error' });
  });
});

describe('API suppressions come from the operator file only', () => {
  it('applies NOIP_IGNORE_FILE', async () => {
    const { mkdtempSync, writeFileSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const f = `${mkdtempSync(`${tmpdir()}/noip-`)}/ign.yaml`;
    writeFileSync(f, 'suppressions:\n  - check: NOIP-NET-001\n    reason: namespaces are isolated by a service mesh\n    owner: platform\n    expires: 2099-01-01\n');
    const r = await request(demo({ ignoreFile: f })).get('/api/scan').set(auth).expect(200);
    expect(r.body.summary.suppressed).toBeGreaterThan(0);
    expect(r.body.findings.some((x: { checkId: string }) => x.checkId === 'NOIP-NET-001')).toBe(false);
  });
});
