import { readFileSync, statSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

type Step = { uses?: string; run?: string; env?: Record<string, string> };
const action = parse(readFileSync('action.yml', 'utf8')) as { runs: { using: string; steps: Step[] }; inputs: Record<string, unknown>; outputs: Record<string, { value: string }> };
const hooks = parse(readFileSync('.pre-commit-hooks.yaml', 'utf8')) as Array<{ id: string; entry: string; language: string; args: string[]; files: string }>;
const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string>; bin: Record<string, string> };

describe('GitHub Action (action.yml)', () => {
  it('is a composite action whose `uses:` are pinned to commit SHAs', () => {
    expect(action.runs.using).toBe('composite');
    const uses = action.runs.steps.flatMap((s) => (s.uses ? [s.uses] : []));
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
  });

  it('never expands inputs inside a run script (script-injection hardening)', () => {
    for (const s of action.runs.steps) if (s.run) expect(s.run).not.toMatch(/\$\{\{\s*(inputs|github\.event)\./);
    const scan = action.runs.steps.find((s) => s.run?.includes('scan'))!;
    for (const name of Object.keys(action.inputs)) expect(Object.values(scan.env ?? {})).toContain(`\${{ inputs.${name} }}`);
  });

  it('exposes every output from the scan step', () => {
    for (const [name, o] of Object.entries(action.outputs)) expect(o.value).toBe(`\${{ steps.scan.outputs.${name} }}`);
  });
});

describe('pre-commit hook', () => {
  it('runs the packaged CLI on staged YAML with a severity gate', () => {
    expect(hooks.map((h) => h.id)).toEqual(['noip']);
    const [h] = hooks;
    expect(h!.language).toBe('script');
    const script = readFileSync(h!.entry.split(' ')[0]!, 'utf8');
    expect(script).toContain('dist/cli.js" scan "$@"');
    expect(statSync(h!.entry.split(' ')[0]!).mode & 0o111).not.toBe(0);
    expect(h!.args).toEqual(['--fail-on', 'high']);
    expect('x/deploy.yaml').toMatch(new RegExp(h!.files));
    // No install-time build hooks: they would run on every `npm ci` (Dockerfile, CI).
    expect(pkg.scripts.prepare).toBeUndefined();
    expect(pkg.bin.noip).toBe('dist/cli.js');
  });
});
