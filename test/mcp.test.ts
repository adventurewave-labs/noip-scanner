import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { describe, expect, it } from 'vitest';
import { createMcpServer } from '../src/mcp.js';
import type { Suppression } from '../src/suppressions.js';

async function connect(opts: { suppressions?: Suppression[] } = {}) {
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
    expect((r.structuredContent!.checks as unknown[]).length).toBe(14);
  });

  it('scan works for demo and manifests, and filters by minSeverity', async () => {
    const c = await connect();
    const all = await call(c, 'scan', { demo: true });
    expect(all.structuredContent!.source).toBe('demo');
    const crit = await call(c, 'scan', { demo: true, minSeverity: 'critical' });
    const f = crit.structuredContent!.findings as Array<{ severity: string }>;
    expect(f.length).toBeGreaterThan(0);
    expect(f.every((x) => x.severity === 'critical')).toBe(true);
    const m = await call(c, 'scan', { manifests: [new URL('./fixtures/misconfig', import.meta.url).pathname] });
    expect(m.structuredContent!.source).toBe('manifests');
    expect(JSON.parse(m.content[0]!.text).findings).toHaveLength(6);
  });

  it('returns a tool error, not a crash, when the cluster is unreachable or flags conflict', async () => {
    const c = await connect();
    const r = await call(c, 'scan', { kubeconfig: '/nonexistent/kubeconfig' });
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
