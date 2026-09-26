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

describe('noip scan -o sarif', () => {
  it('emits SARIF 2.1.0', async () => {
    await main(['node', 'noip', 'scan', '--demo', '-o', 'sarif']);
    const log = JSON.parse(out);
    expect(log.version).toBe('2.1.0');
    expect(log.runs[0].tool.driver.name).toBe('noip');
  });
});

describe('noip scan --manifests', () => {
  it('scans YAML offline and gates with --fail-on', async () => {
    const dir = new URL('./fixtures/misconfig', import.meta.url).pathname;
    expect(await runScan({ output: 'json', manifests: [dir], failOn: 'critical' })).toBe(EXIT.FINDINGS_AT_THRESHOLD);
    expect(JSON.parse(out).source).toBe('manifests');
  });
  it('refuses to mix --manifests with cluster flags', async () => {
    await main(['node', 'noip', 'scan', '--manifests', 'x.yaml', '--demo']);
    expect(process.exitCode).toBe(EXIT.ERROR);
    expect(err).toMatch(/cannot be combined/);
  });
  it('labels manifest reports in markdown with file:line', async () => {
    const dir = new URL('./fixtures/misconfig', import.meta.url).pathname;
    await runScan({ output: 'md', manifests: [dir] });
    expect(out).toContain('OFFLINE MANIFEST SCAN');
    expect(out).toMatch(/10-bad-pods\.yaml:4\)/);
  });
});

describe('noip scan suppressions', () => {
  it('applies --ignore-file, warns on expiry, and --no-ignore disables it', async () => {
    const { mkdtempSync: mk, writeFileSync: wr } = await import('node:fs');
    const f = join(mk(join(tmpdir(), 'noip-')), 'ign.yaml');
    wr(f, 'suppressions:\n  - check: NOIP-POD-004\n    reason: node agents need the host network\n    owner: sre\n    expires: 2099-01-01\n  - check: NOIP-POD-003\n    reason: legacy shared-memory sidecar\n    owner: sre\n    expires: 2000-01-01\n');
    await runScan({ output: 'json', demo: true, ignoreFile: f });
    const r = JSON.parse(out);
    expect(r.summary.suppressed).toBe(1);
    expect(err).toMatch(/warning: suppression expired on 2000-01-01/);
    expect(err).toMatch(/\(\+1 suppressed\)/);
    out = '';
    await runScan({ output: 'json', demo: true, ignoreFile: f, ignore: false });
    expect(JSON.parse(out).summary.suppressed).toBe(0);
  });
});

describe('noip mcp subcommand', () => {
  it('is registered with its options', async () => {
    const { buildCli } = await import('../src/cli.js');
    const mcp = buildCli().commands.find((c) => c.name() === 'mcp')!;
    expect(mcp.options.map((o) => o.long)).toEqual(['--kubeconfig', '--ignore-file', '--no-ignore']);
  });
});

describe('noip diff subcommand', () => {
  it('diffs two report files and gates on new findings', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'noip-diff-'));
    const a = join(dir, 'a.json');
    const b = join(dir, 'b.json');
    await runScan({ output: 'json', demo: true, out: a, excludeNamespace: ['ci'] });
    await runScan({ output: 'json', demo: true, out: b });
    out = '';
    await main(['node', 'noip', 'diff', a, b, '--fail-on', 'critical']);
    expect(out).toContain('# NOIP posture drift');
    expect(process.exitCode).toBe(EXIT.FINDINGS_AT_THRESHOLD);
    process.exitCode = undefined;
    out = '';
    await main(['node', 'noip', 'diff', b, a, '-o', 'json', '--fail-on', 'critical']);
    expect(JSON.parse(out).new).toEqual([]);
    expect(process.exitCode).toBeUndefined();
  });
  it('rejects files that are not NOIP reports', async () => {
    const f = join(mkdtempSync(join(tmpdir(), 'noip-diff-')), 'x.json');
    writeFileSync(f, '{"hello":1}');
    await main(['node', 'noip', 'diff', f, f]);
    expect(process.exitCode).toBe(EXIT.ERROR);
    expect(err).toMatch(/not a NOIP report/);
  });
});

describe('NOIP_DEMO does not override --manifests', () => {
  it('refuses the combination instead of silently scanning demo data', async () => {
    process.env.NOIP_DEMO = '1';
    try {
      await main(['node', 'noip', 'scan', '--manifests', 'test/fixtures/misconfig']);
      expect(process.exitCode).toBe(EXIT.ERROR);
      expect(err).toMatch(/cannot be combined with NOIP_DEMO/);
    } finally {
      delete process.env.NOIP_DEMO;
    }
  });
  it('--min-severity filters and records it in provenance', async () => {
    await runScan({ output: 'json', demo: true, minSeverity: 'critical' });
    const r = JSON.parse(out);
    expect(r.provenance.minSeverity).toBe('critical');
    expect(r.findings.every((f: { severity: string }) => f.severity === 'critical')).toBe(true);
  });
});

describe('noip scan -o html', () => {
  it('writes a self-contained HTML report', async () => {
    await main(['node', 'noip', 'scan', '--demo', '-o', 'html']);
    expect(out.startsWith('<!doctype html>')).toBe(true);
  });
});

describe('noip scan --bundle / verify-bundle', () => {
  it('writes a bundle and verifies it; tampering exits 4', async () => {
    const d = join(mkdtempSync(join(tmpdir(), 'noip-')), 'bundle');
    expect(await runScan({ output: 'json', demo: true, bundle: d })).toBe(EXIT.OK);
    expect(err).toMatch(/evidence bundle written/);
    await main(['node', 'noip', 'verify-bundle', d]);
    expect(process.exitCode ?? 0).toBe(EXIT.OK);
    writeFileSync(join(d, 'report.md'), 'tampered');
    await main(['node', 'noip', 'verify-bundle', d]);
    expect(process.exitCode).toBe(EXIT.VERIFY_FAILED);
    expect(err).toMatch(/bundle FAIL: hash mismatch: report.md/);
  });
});
