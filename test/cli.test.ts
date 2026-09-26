import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT, main, runScan } from '../src/cli.js';

let out = '';
let err = '';
beforeEach(() => {
  out = '';
  err = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((s) => ((out += String(s)), true));
  vi.spyOn(process.stderr, 'write').mockImplementation((s) => ((err += String(s)), true));
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe('noip scan (R-7)', () => {
  it('emits JSON to stdout in demo mode', async () => {
    expect(await runScan({ output: 'json', demo: true })).toBe(EXIT.OK);
    const r = JSON.parse(out);
    expect(r.source).toBe('demo');
    expect(err).toMatch(/demo scan: \d+ finding/);
  });

  it('writes markdown to a file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-'));
    const file = join(dir, 'r.md');
    await runScan({ output: 'md', out: file, demo: true });
    expect(readFileSync(file, 'utf8')).toMatch(/^# NOIP posture report/);
    expect(out).toBe('');
  });

  it('--fail-on exits 2 when findings reach the threshold', async () => {
    expect(await runScan({ output: 'json', demo: true, failOn: 'critical' })).toBe(EXIT.FINDINGS_AT_THRESHOLD);
    expect(await runScan({ output: 'json', demo: true, excludeNamespace: ['ci', 'monitoring', 'payments', 'shop', 'default'], failOn: 'critical' })).toBe(EXIT.OK);
  });

  it('--netinspect merges a network section', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-'));
    const f = join(dir, 'n.json');
    writeFileSync(f, JSON.stringify({ tool: 'k8s-netinspect', version: '0.1.0', cni: 'flannel', checks: [{ name: 'pod connectivity', status: 'pass' }] }));
    await runScan({ output: 'json', demo: true, netinspect: f });
    expect(JSON.parse(out).network).toMatchObject({ source: 'k8s-netinspect', cni: 'flannel' });
  });

  it('--explain without a key warns and sets explanation to null; scan still succeeds', async () => {
    const keys = ['ANTHROPIC_API_KEY', 'NOIP_LLM_API_KEY'].map((k) => [k, process.env[k]] as const);
    for (const [k] of keys) delete process.env[k];
    try {
      expect(await runScan({ output: 'json', demo: true, explain: true })).toBe(EXIT.OK);
      expect(JSON.parse(out).explanation).toBeNull();
      expect(err).toMatch(/No LLM provider key configured/);
    } finally {
      for (const [k, v] of keys) if (v !== undefined) process.env[k] = v;
    }
  });

  it('exits 3 with K8sUnavailable when no cluster is reachable', async () => {
    await main(['node', 'noip', 'scan', '--kubeconfig', '/nonexistent/config']);
    expect(process.exitCode).toBe(EXIT.K8S_UNAVAILABLE);
    expect(err).toMatch(/K8sUnavailable/);
  });

  it('exits 1 on other errors', async () => {
    await main(['node', 'noip', 'scan', '--demo', '--netinspect', '/nonexistent/file.json']);
    expect(process.exitCode).toBe(EXIT.ERROR);
  });

  it('parses flags through the real CLI', async () => {
    await main(['node', 'noip', 'scan', '--demo', '-o', 'md']);
    expect(out).toContain('DEMO DATA');
  });
});
