import type { z } from 'zod';
import { LLMNotConfigured } from '../errors.js';
import { parseJsonLoose } from './schema.js';

export class LLMSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LLMSchemaError';
  }
}

/** Provider-agnostic seam (PRD R-6). Adapters only move text; parsing and validation are shared. */
export interface LLMProvider {
  readonly name: string;
  readonly model: string;
  complete<T>(prompt: string, schema: z.ZodType<T>, system?: string): Promise<T>;
}

export abstract class TextProvider implements LLMProvider {
  abstract readonly name: string;
  abstract readonly model: string;
  protected abstract completeText(prompt: string, system: string): Promise<string>;

  async complete<T>(prompt: string, schema: z.ZodType<T>, system = ''): Promise<T> {
    const text = await this.completeText(prompt, system);
    const json = parseJsonLoose(text);
    const res = schema.safeParse(json);
    if (!res.success) throw new LLMSchemaError(`LLM output failed schema validation: ${res.error.issues.map((i) => i.path.join('.') + ' ' + i.message).join('; ')}`);
    return res.data;
  }
}

export interface LLMConfig {
  provider: 'anthropic' | 'openai-compatible';
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

/** Single place the default model is pinned. Override with NOIP_LLM_MODEL. */
export const DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-5';

export function llmConfigFromEnv(env: NodeJS.ProcessEnv = process.env): LLMConfig {
  const provider = (env.NOIP_LLM_PROVIDER ?? 'anthropic') as LLMConfig['provider'];
  if (provider !== 'anthropic' && provider !== 'openai-compatible') {
    throw new Error(`NOIP_LLM_PROVIDER must be "anthropic" or "openai-compatible", got "${String(provider)}"`);
  }
  if (provider === 'anthropic') {
    return { provider, model: env.NOIP_LLM_MODEL || DEFAULT_ANTHROPIC_MODEL, apiKey: env.NOIP_LLM_API_KEY || env.ANTHROPIC_API_KEY };
  }
  return { provider, model: env.NOIP_LLM_MODEL ?? '', apiKey: env.NOIP_LLM_API_KEY, baseUrl: env.NOIP_LLM_BASE_URL };
}

export type ProviderFactory = (cfg: LLMConfig) => LLMProvider;

/** Returns a provider, or throws LLMNotConfigured when no key (or, for openai-compatible, no base URL/model) is set. */
export async function createProvider(cfg: LLMConfig = llmConfigFromEnv()): Promise<LLMProvider> {
  if (!cfg.apiKey) throw new LLMNotConfigured();
  if (cfg.provider === 'anthropic') {
    const { AnthropicProvider } = await import('./anthropic.js');
    return new AnthropicProvider(cfg.apiKey, cfg.model);
  }
  if (!cfg.baseUrl || !cfg.model) throw new LLMNotConfigured('openai-compatible provider needs NOIP_LLM_BASE_URL, NOIP_LLM_API_KEY and NOIP_LLM_MODEL.');
  const { OpenAICompatibleProvider } = await import('./openai-compatible.js');
  return new OpenAICompatibleProvider(cfg.baseUrl, cfg.apiKey, cfg.model);
}
