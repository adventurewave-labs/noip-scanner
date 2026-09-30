import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { NetworkSection } from '../types.js';

/**
 * Input contract for `noip scan --netinspect <file>` (schemas/netinspect-input.schema.json).
 * k8s-netinspect does not emit JSON yet; this is the shape NOIP accepts so the two tools can meet in the middle.
 */
export const NetinspectInput = z.object({
  tool: z.literal('k8s-netinspect').optional(),
  version: z.string().optional(),
  cni: z.string().optional(),
  checks: z
    .array(
      z.object({
        name: z.string().min(1),
        status: z.enum(['pass', 'warn', 'fail', 'info']),
        detail: z.string().optional(),
        resource: z.string().optional(),
      }),
    )
    .max(500),
});

export function ingestNetinspect(raw: string): NetworkSection {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`--netinspect: not valid JSON (${(err as Error).message})`, { cause: err });
  }
  const res = NetinspectInput.safeParse(parsed);
  if (!res.success) throw new Error(`--netinspect: input does not match schemas/netinspect-input.schema.json: ${res.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  return {
    source: 'k8s-netinspect',
    toolVersion: res.data.version,
    cni: res.data.cni,
    inputSha256: createHash('sha256').update(raw).digest('hex'),
    checks: res.data.checks,
  };
}
