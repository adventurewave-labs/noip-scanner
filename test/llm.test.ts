import { describe, expect, it, vi } from 'vitest';
import type { z } from 'zod';
import { LLMNotConfigured } from '../src/errors.js';
import { buildPrompt, explain } from '../src/llm/explain.js';
import { OpenAICompatibleProvider } from '../src/llm/openai-compatible.js';
import { createProvider, DEFAULT_ANTHROPIC_MODEL, llmConfigFromEnv, LLMSchemaError, TextProvider, type LLMProvider } from '../src/llm/provider.js';
import { llmPayload, redact, scrubString } from '../src/llm/redact.js';
import { parseJsonLoose } from '../src/llm/schema.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { golden, snapshotFromMisconfigFixtures } from './helpers.js';

const SECRET = golden.seededSecretValue;
const demo = () => buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-01-01T00:00:00Z') });

/** Fake provider: records prompts, returns canned text. */
class FakeProvider extends TextProvider {
  readonly name = 'fake';
  readonly model = 'fake-1';
  prompts: string[] = [];
  constructor(private readonly reply: string | (() => never)) {
    super();
  }
  protected async completeText(prompt: string, system: string): Promise<string> {
    this.prompts.push(system + '\n' + prompt);
    return typeof this.reply === 'string' ? this.reply : this.reply();
  }
}

describe('redaction (R-6)', () => {
  it('drops env values, annotations and data fields and scrubs token-shaped strings', () => {
    const input = {
      metadata: { name: 'p', annotations: { 'kubectl.kubernetes.io/last-applied-configuration': SECRET } },
      env: [{ name: 'PW', value: SECRET }],
      data: { password: Buffer.from(SECRET).toString('base64') },
      stringData: { password: SECRET },
      note: `password=${SECRET} and Bearer abcdefghijklmnop123 and AKIAABCDEFGHIJKLMNOP`,
      nested: [{ value: SECRET }],
    };
    const out = JSON.stringify(redact(input));
    expect(out).not.toContain(SECRET);
    expect(out).not.toContain('AKIAABCDEFGHIJKLMNOP');
    expect(out).toContain('"name":"p"');
    expect(scrubString('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----')).toBe('[REDACTED:PEM]');
    expect(scrubString('token: ghp_abcdefghijklmnopqrstuvwxyz0123')).not.toContain('ghp_');
  });

  it('outgoing prompt for the seeded fixtures never contains the seeded secret value (snapshot)', async () => {
    const report = buildReport(snapshotFromMisconfigFixtures(), 'live', { now: new Date('2026-01-01T00:00:00Z') });
    // Worst case: something upstream smuggled the value into evidence text.
    report.findings[0]!.evidence += ` password=${SECRET}`;
    const fake = new FakeProvider('{"summary":"ok","priorities":[],"caveats":[]}');
    await explain(report, fake);
    expect(fake.prompts).toHaveLength(1);
    expect(fake.prompts[0]).not.toContain(SECRET);
    expect(fake.prompts[0]).toMatchSnapshot();
  });

  it('caps the number of findings sent', () => {
    const r = demo();
    r.findings = Array.from({ length: 70 }, () => r.findings[0]!);
    const p = llmPayload(r);
    expect(p.findings).toHaveLength(60);
    expect(p.truncatedFindings).toBe(10);
  });
});

describe('explain()', () => {
  it('returns a validated explanation and drops priorities citing unknown findings', async () => {
    const r = demo();
    const log = vi.fn();
    const reply = { summary: 'Top risk is the privileged debug pod.', priorities: [{ findingId: r.findings[0]!.id, why: 'root on node', fix: 'delete it' }, { findingId: 'NOIP-POD-999:made-up', why: 'x', fix: 'y' }] };
    const out = await explain(r, new FakeProvider('Sure! ```json\n' + JSON.stringify(reply) + '\n```'), log);
    expect(out).toEqual({ summary: reply.summary, priorities: [reply.priorities[0]], caveats: [] });
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/unknown finding IDs/));
  });

  it('returns null on schema failure without touching the deterministic report', async () => {
    const r = demo();
    const before = JSON.stringify(r);
    expect(await explain(r, new FakeProvider('{"summary": 42}'))).toBeNull();
    expect(await explain(r, new FakeProvider('not json at all'))).toBeNull();
    expect(JSON.stringify(r)).toBe(before);
  });

  it('returns null when the provider throws', async () => {
    expect(await explain(demo(), new FakeProvider(() => { throw new Error('HTTP 404 model not found'); }))).toBeNull();
  });

  it('prompt tells the model mappings are not an attestation', () => {
    expect(buildPrompt(demo())).toContain('"failedControls"');
  });
});

describe('provider seam', () => {
  it('defaults to anthropic with the pinned model and no key -> not configured', async () => {
    const cfg = llmConfigFromEnv({});
    expect(cfg).toEqual({ provider: 'anthropic', model: DEFAULT_ANTHROPIC_MODEL, apiKey: undefined });
    await expect(createProvider(cfg)).rejects.toBeInstanceOf(LLMNotConfigured);
  });

  it('swaps provider through config alone', async () => {
    const a = await createProvider(llmConfigFromEnv({ ANTHROPIC_API_KEY: 'k', NOIP_LLM_MODEL: 'claude-x' }));
    expect([a.name, a.model]).toEqual(['anthropic', 'claude-x']);
    const o = await createProvider(llmConfigFromEnv({ NOIP_LLM_PROVIDER: 'openai-compatible', NOIP_LLM_API_KEY: 'k', NOIP_LLM_BASE_URL: 'https://openrouter.ai/api/v1', NOIP_LLM_MODEL: 'z-ai/glm-4.6' }));
    expect([o.name, o.model]).toEqual(['openai-compatible', 'z-ai/glm-4.6']);
    await expect(createProvider(llmConfigFromEnv({ NOIP_LLM_PROVIDER: 'openai-compatible', NOIP_LLM_API_KEY: 'k' }))).rejects.toBeInstanceOf(LLMNotConfigured);
    expect(() => llmConfigFromEnv({ NOIP_LLM_PROVIDER: 'mystery' })).toThrow(/must be/);
  });

  it('openai-compatible adapter posts chat/completions and validates output', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ choices: [{ message: { content: '{"summary":"s","priorities":[]}' } }] }), { status: 200 }));
    const p: LLMProvider = new OpenAICompatibleProvider('https://example.test/v1/', 'key', 'm', fetchImpl as unknown as typeof fetch);
    const { ExplanationSchema } = await import('../src/llm/schema.js');
    await expect(p.complete('hi', ExplanationSchema as z.ZodType<unknown>, 'sys')).resolves.toEqual({ summary: 's', priorities: [], caveats: [] });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://example.test/v1/chat/completions');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer key');
    const bad = new OpenAICompatibleProvider('https://e.test', 'k', 'm', (async () => new Response('', { status: 500 })) as unknown as typeof fetch);
    await expect(bad.complete('x', ExplanationSchema)).rejects.toThrow(/HTTP 500/);
  });

  it('schema errors surface as LLMSchemaError', async () => {
    const { ExplanationSchema } = await import('../src/llm/schema.js');
    await expect(new FakeProvider('{}').complete('x', ExplanationSchema)).rejects.toBeInstanceOf(LLMSchemaError);
  });

  it('parseJsonLoose handles fences, prose and garbage', () => {
    expect(parseJsonLoose('{"a":1}')).toEqual({ a: 1 });
    expect(parseJsonLoose('here:\n```json\n{"a":2}\n```')).toEqual({ a: 2 });
    expect(parseJsonLoose('prefix {"a":3} suffix')).toEqual({ a: 3 });
    expect(parseJsonLoose('nope')).toBeUndefined();
  });
});
