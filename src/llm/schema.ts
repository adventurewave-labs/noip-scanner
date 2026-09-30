import { z } from 'zod';

export const ExplanationSchema = z.object({
  summary: z.string().min(1).max(2000),
  priorities: z
    .array(z.object({ findingId: z.string().min(1), why: z.string().min(1).max(600), fix: z.string().min(1).max(600) }))
    .max(10),
  caveats: z.array(z.string().max(400)).max(5).default([]),
});

export type ExplanationOut = z.infer<typeof ExplanationSchema>;

/** Tolerates ```json fences and prose around a single JSON object. Returns undefined if nothing parses. */
export function parseJsonLoose(text: string): unknown {
  const candidates = [text.trim()];
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  if (fenced?.[1]) candidates.push(fenced[1].trim());
  const first = text.indexOf('{');
  const last = text.lastIndexOf('}');
  if (first >= 0 && last > first) candidates.push(text.slice(first, last + 1));
  for (const c of candidates) {
    try {
      return JSON.parse(c);
    } catch {
      /* try next */
    }
  }
  return undefined;
}
