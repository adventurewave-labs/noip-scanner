import { Validator } from '@seriousme/openapi-schema-validator';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsPlugin from 'ajv-formats';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/api/app.js';
import { openApiDocument } from '../src/api/openapi.js';
import { K8sUnavailable, LLMNotConfigured } from '../src/errors.js';
import { TextProvider } from '../src/llm/provider.js';

const TOKEN = 'contract-token-0123456789';
const auth = { Authorization: `Bearer ${TOKEN}` };
const spec = openApiDocument();

class Fake extends TextProvider {
  readonly name = 'fake';
  readonly model = 'fake';
  protected async completeText() {
    return '{"summary":"ok","priorities":[]}';
  }
}
const down = async () => {
  throw new K8sUnavailable('connect ECONNREFUSED');
};
const demo = (llm = false) => createApp({ token: TOKEN, demo: true, provider: llm ? async () => new Fake() : async () => { throw new LLMNotConfigured(); } });
const live = () => createApp({ token: TOKEN, demo: false, snapshot: down, probe: down, provider: async () => { throw new LLMNotConfigured(); } });

/** Validate a response body against the schema the spec declares for (path, method, status). */
function conforms(path: string, method: 'get' | 'post', status: number, body: unknown) {
  const op = (spec.paths as Record<string, Record<string, { responses: Record<string, { content?: { 'application/json': { schema: object } } }> }>>)[path]![method]!;
  const schema = op.responses[String(status)]?.content?.['application/json']?.schema;
  if (!schema) throw new Error(`spec has no JSON response for ${method.toUpperCase()} ${path} ${status}`);
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ((addFormatsPlugin as unknown as { default: (a: Ajv2020) => void }).default)(ajv);
  ajv.addSchema({ ...spec, $id: 'openapi' }, 'openapi');
  const validate = ajv.compile({ $ref: `openapi#${(schema as { $ref: string }).$ref.slice(1)}` });
  const ok = validate(body);
  if (!ok) throw new Error(JSON.stringify(validate.errors?.slice(0, 3)));
}

describe('OpenAPI document', () => {
  it('is a valid OpenAPI 3.1 document', async () => {
    const v = new Validator();
    const res = await v.validate(structuredClone(spec));
    expect(res.errors ?? [], JSON.stringify(res.errors)).toEqual([]);
    expect(res.valid).toBe(true);
    expect(v.version).toBe('3.1');
  });

  it('is served publicly at /openapi.json', async () => {
    const r = await request(live()).get('/openapi.json').expect(200);
    expect(r.body.openapi).toBe('3.1.0');
  });

  it('documents every route the app exposes', () => {
    const app = live() as unknown as { router: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> }; handle?: { stack?: Array<{ route?: { path: string; methods: Record<string, boolean> } }> } }> } };
    const routes: string[] = [];
    for (const layer of app.router.stack) {
      if (layer.route) for (const m of Object.keys(layer.route.methods)) routes.push(`${m} ${layer.route.path}`);
      for (const sub of layer.handle?.stack ?? []) if (sub.route) for (const m of Object.keys(sub.route.methods)) routes.push(`${m} /api${sub.route.path}`);
    }
    expect(routes.sort()).toEqual(['get /', 'get /api/discovery/cluster', 'get /api/scan', 'get /health', 'get /openapi.json', 'post /api/report/explain']);
    const documented = Object.entries(spec.paths).flatMap(([p, ops]) => Object.keys(ops).map((m) => `${m} ${p}`));
    for (const r of routes.filter((x) => x !== 'get /')) expect(documented).toContain(r);
  });
});

describe('contract: responses conform to the OpenAPI schemas', () => {
  it('GET /health (ok in demo, degraded live)', async () => {
    conforms('/health', 'get', 200, (await request(demo()).get('/health')).body);
    conforms('/health', 'get', 200, (await request(live()).get('/health')).body);
  });
  it('GET /api/scan 200 / 401 / 503', async () => {
    conforms('/api/scan', 'get', 200, (await request(demo()).get('/api/scan?includeSystem=1').set(auth).expect(200)).body);
    conforms('/api/scan', 'get', 401, (await request(demo()).get('/api/scan').expect(401)).body);
    conforms('/api/scan', 'get', 503, (await request(live()).get('/api/scan').set(auth).expect(503)).body);
  });
  it('GET /api/discovery/cluster 200 / 503', async () => {
    conforms('/api/discovery/cluster', 'get', 200, (await request(demo()).get('/api/discovery/cluster').set(auth).expect(200)).body);
    conforms('/api/discovery/cluster', 'get', 503, (await request(live()).get('/api/discovery/cluster').set(auth).expect(503)).body);
  });
  it('POST /api/report/explain 200 / 501', async () => {
    conforms('/api/report/explain', 'post', 200, (await request(demo(true)).post('/api/report/explain').set(auth).expect(200)).body);
    conforms('/api/report/explain', 'post', 501, (await request(demo()).post('/api/report/explain').set(auth).expect(501)).body);
  });
});
