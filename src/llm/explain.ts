import type { Explanation, Report } from '../types.js';
import type { LLMProvider } from './provider.js';
import { llmPayload } from './redact.js';
import { ExplanationSchema } from './schema.js';

export const SYSTEM_PROMPT = [
  'You are a Kubernetes security reviewer explaining the output of a deterministic posture scanner to an engineering lead.',
  'Use ONLY the findings provided. Do not invent findings, resources, CVEs or compliance claims.',
  'Control mappings are reference mappings, not an attestation — never state that the cluster is or is not compliant.',
  'Reply with a single JSON object and nothing else:',
  '{"summary": string (<= 120 words), "priorities": [{"findingId": string (copied exactly from input), "why": string, "fix": string}] (<= 10, most urgent first), "caveats": string[] (<= 5)}',
].join('\n');

export function buildPrompt(report: Report): string {
  return `Scan results (redacted):\n${JSON.stringify(llmPayload(report), null, 2)}`;
}

/**
 * Returns a validated explanation, or null on any provider or schema failure.
 * The deterministic report is never altered by this step.
 */
export async function explain(report: Report, provider: LLMProvider, log: (m: string) => void = () => {}): Promise<Explanation | null> {
  try {
    const out = await provider.complete(buildPrompt(report), ExplanationSchema, SYSTEM_PROMPT);
    const known = new Set(report.findings.map((f) => f.id));
    const priorities = out.priorities.filter((p) => known.has(p.findingId));
    if (priorities.length < out.priorities.length) log(`dropped ${out.priorities.length - priorities.length} LLM priorities citing unknown finding IDs`);
    return { summary: out.summary, priorities, caveats: out.caveats };
  } catch (err) {
    log(`LLM explanation unavailable: ${(err as Error).message}`);
    return null;
  }
}
