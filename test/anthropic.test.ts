import { describe, expect, it, vi } from 'vitest';

const create = vi.fn(async () => ({ content: [{ type: 'text', text: '{"summary":"s","priorities":[]}' }] }));
vi.mock('@anthropic-ai/sdk', () => ({ default: class { messages = { create }; } }));

describe('anthropic adapter', () => {
  it('sends the model from config and the system prompt separately', async () => {
    const { AnthropicProvider } = await import('../src/llm/anthropic.js');
    const { ExplanationSchema } = await import('../src/llm/schema.js');
    const p = new AnthropicProvider('key', 'claude-test');
    await expect(p.complete('user prompt', ExplanationSchema, 'system prompt')).resolves.toEqual({ summary: 's', priorities: [], caveats: [] });
    expect(create).toHaveBeenCalledWith({ model: 'claude-test', max_tokens: 2048, system: 'system prompt', messages: [{ role: 'user', content: 'user prompt' }] });
  });
});
