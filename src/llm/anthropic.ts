import Anthropic from '@anthropic-ai/sdk';
import { TextProvider } from './provider.js';

export class AnthropicProvider extends TextProvider {
  readonly name = 'anthropic';
  private readonly client: Anthropic;

  constructor(
    apiKey: string,
    readonly model: string,
  ) {
    super();
    this.client = new Anthropic({ apiKey, timeout: 60_000, maxRetries: 2 });
  }

  protected async completeText(prompt: string, system: string): Promise<string> {
    const msg = await this.client.messages.create({
      model: this.model,
      max_tokens: 2048,
      ...(system ? { system } : {}),
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content.map((b) => (b.type === 'text' ? b.text : '')).join('');
  }
}
