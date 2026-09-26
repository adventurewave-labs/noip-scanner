import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { createMcpServer } from '../src/mcp.js';
import type { Suppression } from '../src/suppressions.js';

async function connect(opts: { suppressions?: Suppression[]; kubeconfig?: string; root?: string } = {}) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([createMcpServer(opts).connect(a), client.connect(b)]);
  return client;
}
type Out = { isError?: boolean; structuredContent?: Record<string, unknown>; content: Array<{ text: string }> };
const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => (await c.callTool({ name, arguments: args })) as Out;

describe('noip mcp', () => {
  it('lists three read-only tools', async () => {
    const { tools } = await (await connect()).listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['explain_finding', 'list_checks', 'scan']);
    for (const t of tools) expect(t.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
  });

  it('list_checks returns the catalog', async () => {
    const r = await call(await connect(), 'list_checks');
    expect((r.structuredContent!.checks as unknown[]).length).toBe(15);
  });

  it('scan works for demo and manifests, and filters by minSeverity', async () => {
    const c = await connect();
    const all = await call(c, 'scan', { demo: true });
    expect(all.structuredContent!.source).toBe('demo');
    const crit = await call(c, 'scan', { demo: true, minSeverity: 'critical' });
    const f = crit.structuredContent!.findings as Array<{ severity: string }>;
    expect(f.length).toBeGreaterThan(0);
    expect(f.every((x) => x.severity === 'critical')).toBe(true);
    const m = await call(c, 'scan', { manifests: ['test/fixtures/misconfig'] });
    expect(m.structuredContent!.source).toBe('manifests');
    expect(JSON.parse(m.content[0]!.text).findings).toHaveLength(7);
  });

  it('returns a tool error, not a crash, when the cluster is unreachable or flags conflict', async () => {
    const c = await connect();
    const r = await call(await connect({ kubeconfig: '/nonexistent/kubeconfig' }), 'scan', {});
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toMatch(/^K8sUnavailable:/);
    expect((await call(c, 'scan', { demo: true, manifests: ['x'] })).isError).toBe(true);
  });

  it('explain_finding returns the finding with control context, and reports suppression status', async () => {
    const id = 'NOIP-POD-001:Pod/ci/debug-shell/shell';
    const r = await call(await connect(), 'explain_finding', { demo: true, findingId: id });
    expect(r.structuredContent).toMatchObject({ status: 'active', finding: { id }, controls: [{ id: 'CIS-5.2.1', status: 'fail', soc2: ['CC6.1', 'CC6.6'] }] });
    const sup = await connect({ suppressions: [{ id, reason: 'break-glass debug pod, removed in OPS-7', owner: 'sre', expires: '2099-01-01' }] });
    const s = await call(sup, 'explain_finding', { demo: true, findingId: id });
    expect(s.structuredContent).toMatchObject({ status: 'suppressed', suppression: { owner: 'sre' } });
    const missing = await call(sup, 'explain_finding', { demo: true, findingId: 'NOIP-POD-001:Pod/x/y/z' });
    expect(missing.isError).toBe(true);
    expect(missing.content[0]!.text).toMatch(/^NotFound:/);
  });
});

describe('noip mcp hardening (review fixes)', () => {
  it('does not let a tool call choose the kubeconfig (exec plugins could run commands)', async () => {
    const { tools } = await (await connect()).listTools();
    for (const t of tools) expect(Object.keys((t.inputSchema as { properties?: object }).properties ?? {})).not.toContain('kubeconfig');
  });

  it('confines manifest paths to the working directory, including via symlinks', async () => {
    const { confinePaths } = await import('../src/mcp.js');
    const { mkdtempSync, mkdirSync, symlinkSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const root = mkdtempSync(join(tmpdir(), 'noip-root-'));
    mkdirSync(join(root, 'k8s'));
    symlinkSync('/etc', join(root, 'escape'));
    expect(confinePaths(['k8s'], root)).toHaveLength(1);
    expect(() => confinePaths(['../'], root)).toThrow(/outside the working directory/);
    expect(() => confinePaths(['/etc'], root)).toThrow(/outside the working directory/);
    expect(() => confinePaths(['escape'], root)).toThrow(/outside the working directory/);
    expect(() => confinePaths(['missing'], root)).toThrow(/not found/);
    const r = await call(await connect({ root }), 'scan', { manifests: ['/etc'] });
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toMatch(/^Forbidden:/);
  });

  it('minSeverity keeps summary and controls consistent with the returned findings', async () => {
    const r = (await call(await connect(), 'scan', { demo: true, minSeverity: 'critical' })).structuredContent as {
      findings: Array<{ id: string }>; summary: { findings: number; bySeverity: Record<string, number> };
      controls: Array<{ findingIds: string[] }>; provenance: { minSeverity: string };
    };
    expect(r.summary.findings).toBe(r.findings.length);
    expect(r.summary.bySeverity.high).toBe(0);
    const ids = new Set(r.findings.map((f) => f.id));
    for (const c of r.controls) for (const id of c.findingIds) expect(ids.has(id)).toBe(true);
    expect(r.provenance.minSeverity).toBe('critical');
  });
});
