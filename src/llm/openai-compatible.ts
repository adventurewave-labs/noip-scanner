import { TextProvider } from './provider.js';

/** Any OpenAI-compatible /chat/completions endpoint (OpenRouter, GLM, vLLM, …). No SDK dependency. */
export class OpenAICompatibleProvider extends TextProvider {
  readonly name = 'openai-compatible';

  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    readonly model: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    super();
  }

  protected async completeText(prompt: string, system: string): Promise<string> {
    const url = `${this.baseUrl.replace(/\/+$/, '')}/chat/completions`;
    const res = await this.fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 2048,
        messages: [...(system ? [{ role: 'system', content: system }] : []), { role: 'user', content: prompt }],
      }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`openai-compatible provider returned HTTP ${res.status}`);
    const body = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return body.choices?.[0]?.message?.content ?? '';
  }
}
