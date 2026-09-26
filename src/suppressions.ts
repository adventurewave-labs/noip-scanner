import { existsSync, readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { z } from 'zod';
import type { Finding } from './types.js';

/**
 * Accepted-risk handling. Every suppression must say why, who owns it and when it expires, so accepted
 * risk is reviewed rather than forgotten. Expired entries stop applying and are reported as warnings.
 */
export const DEFAULT_IGNORE_FILE = '.noip-ignore.yaml';

const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'expires must be YYYY-MM-DD');

export const SuppressionSchema = z
  .object({
    id: z.string().min(1).optional(),
    check: z.string().regex(/^NOIP-[A-Z]+-\d{3}$/).optional(),
    resource: z.string().min(1).optional(),
    reason: z.string().min(10, 'reason must explain the accepted risk (>= 10 chars)'),
    owner: z.string().min(1),
    expires: z.union([isoDate, z.date().transform((d) => d.toISOString().slice(0, 10))]),
  })
  .strict()
  .refine((s) => Boolean(s.id) !== Boolean(s.check), { message: 'set exactly one of `id` (a finding ID) or `check` (+ optional `resource` glob)' })
  .refine((s) => !(s.id && s.resource), { message: '`resource` only applies together with `check`' });

export const IgnoreFileSchema = z.object({ suppressions: z.array(SuppressionSchema).max(500) }).strict();

export type Suppression = z.infer<typeof SuppressionSchema>;

export interface SuppressedFinding {
  finding: Finding;
  suppression: { reason: string; owner: string; expires: string; rule: string };
}

export interface SuppressionOutcome {
  active: Finding[];
  suppressed: SuppressedFinding[];
  /** Human-readable warnings: expired entries, entries that matched nothing. */
  warnings: string[];
}

/** `*` matches within one path segment, `**` across segments. Everything else is literal. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else re += '[^/]*';
    } else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

const ruleLabel = (s: Suppression) => s.id ?? `${s.check}${s.resource ? ` ${s.resource}` : ''}`;

function matches(s: Suppression, f: Finding): boolean {
  if (s.id) return s.id === f.id;
  if (s.check !== f.checkId) return false;
  if (!s.resource) return true;
  return globToRegExp(s.resource).test(f.id.slice(f.checkId.length + 1));
}

export function applySuppressions(findings: Finding[], suppressions: Suppression[], now: Date = new Date()): SuppressionOutcome {
  const today = now.toISOString().slice(0, 10);
  const live = suppressions.filter((s) => s.expires >= today);
  const warnings = suppressions
    .filter((s) => s.expires < today)
    .map((s) => `suppression expired on ${s.expires} (owner ${s.owner}): ${ruleLabel(s)}; its findings are active again`);

  const used = new Set<Suppression>();
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const hits = live.filter((x) => matches(x, f));
    const s = hits[0];
    if (!s) {
      active.push(f);
      continue;
    }
    for (const h of hits) used.add(h); // overlapping entries are all "in use", not stale
    suppressed.push({ finding: f, suppression: { reason: s.reason, owner: s.owner, expires: s.expires, rule: ruleLabel(s) } });
  }
  for (const s of live) if (!used.has(s)) warnings.push(`suppression matched no findings (stale?): ${ruleLabel(s)}`);
  return { active, suppressed, warnings };
}

export class IgnoreFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IgnoreFileError';
  }
}

/** Load an ignore file. An explicit path must exist; the default path is optional. */
export function loadIgnoreFile(path?: string): Suppression[] {
  const file = path ?? DEFAULT_IGNORE_FILE;
  if (!existsSync(file)) {
    if (path) throw new IgnoreFileError(`ignore file not found: ${path}`);
    return [];
  }
  let raw: unknown;
  try {
    raw = parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new IgnoreFileError(`${file}: invalid YAML (${(err as Error).message.split('\n')[0]})`);
  }
  const res = IgnoreFileSchema.safeParse(raw ?? { suppressions: [] });
  if (!res.success) {
    throw new IgnoreFileError(`${file}: ${res.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')}`);
  }
  return res.data.suppressions;
}
