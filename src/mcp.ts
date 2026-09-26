import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { ALL_CHECKS } from './checks/index.js';
import { CONTROLS, MAPPING_DISCLAIMER } from './checks/controls.js';
import { scannerInfo } from './report/provenance.js';
import { buildReport, getSnapshot } from './scan.js';
import { SEVERITIES } from './types.js';
import type { Suppression } from './suppressions.js';

/**
 * `noip mcp`: expose the deterministic scanner to agents over MCP (stdio).
 * Every tool is read-only and uses the caller's kubeconfig/RBAC. No LLM is involved — the calling agent does the reasoning.
 */

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

const target = {
  kubeconfig: z.string().optional().describe('Path to a kubeconfig. Default: $KUBECONFIG, ~/.kube/config, or in-cluster.'),
  context: z.string().optional().describe('kubeconfig context to use.'),
  manifests: z.array(z.string()).optional().describe('Scan these YAML files/directories offline instead of a cluster.'),
  demo: z.boolean().optional().describe('Scan the bundled fictional demo cluster (source: "demo").'),
  includeSystemNamespaces: z.boolean().optional().describe('Also scan kube-system, kube-public, kube-node-lease.'),
};

type Target = { kubeconfig?: string; context?: string; manifests?: string[]; demo?: boolean; includeSystemNamespaces?: boolean };

const json = (value: unknown): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
  structuredContent: value as Record<string, unknown>,
});
const fail = (err: unknown): CallToolResult => ({
  isError: true,
  content: [{ type: 'text', text: `${(err as { code?: string }).code ?? (err as Error).name}: ${(err as Error).message}` }],
});

export function createMcpServer(opts: { suppressions?: Suppression[] } = {}): McpServer {
  const server = new McpServer({ name: 'noip', version: scannerInfo().version });

  async function report(t: Target) {
    if (t.manifests?.length && (t.demo || t.kubeconfig || t.context)) throw new Error('manifests cannot be combined with demo, kubeconfig or context');
    const scanOpts = { ...t, suppressions: opts.suppressions };
    const { snapshot, source } = await getSnapshot(scanOpts);
    return buildReport(snapshot, source, scanOpts);
  }

  server.registerTool(
    'scan',
    {
      title: 'Scan Kubernetes posture',
      description:
        'Run NOIP\'s deterministic, read-only posture checks against a live cluster (current kubeconfig), offline manifests, or the demo fixture. ' +
        'Returns the full report: provenance, summary, findings with evidence, CIS control status. Findings are facts; control mappings are references, not an attestation.',
      inputSchema: { ...target, minSeverity: z.enum(SEVERITIES as unknown as [string, ...string[]]).optional().describe('Only return findings at or above this severity.') },
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const r = await report(args);
        if (args.minSeverity) {
          const limit = SEVERITIES.indexOf(args.minSeverity as (typeof SEVERITIES)[number]);
          r.findings = r.findings.filter((f) => SEVERITIES.indexOf(f.severity) <= limit);
        }
        return json(r);
      } catch (err) {
        return fail(err);
      }
    },
  );

  server.registerTool(
    'list_checks',
    {
      title: 'List NOIP checks',
      description: 'The catalog of checks NOIP runs: id, title, severity, category, CIS controls and remediation.',
      annotations: READ_ONLY,
    },
    async () =>
      json({
        checks: ALL_CHECKS.map(({ id, title, severity, category, controls, remediation }) => ({ id, title, severity, category, controls, remediation })),
        mappingDisclaimer: MAPPING_DISCLAIMER,
      }),
  );

  server.registerTool(
    'explain_finding',
    {
      title: 'Explain one finding',
      description:
        'Re-scan the same target and return one finding by id with its check, remediation and control context (SOC 2 / HIPAA reference mappings). Deterministic; no LLM call.',
      inputSchema: { ...target, findingId: z.string().min(1).describe('A finding id from a scan result, e.g. "NOIP-POD-001:Pod/ci/debug-shell/shell".') },
      annotations: READ_ONLY,
    },
    async ({ findingId, ...t }) => {
      try {
        const r = await report(t);
        const finding = r.findings.find((f) => f.id === findingId);
        const suppressed = r.suppressed?.find((x) => x.finding.id === findingId);
        const f = finding ?? suppressed?.finding;
        if (!f) return fail(Object.assign(new Error(`finding ${findingId} not present in this ${r.source} scan (it may have been fixed)`), { code: 'NotFound' }));
        return json({
          finding: f,
          status: finding ? 'active' : 'suppressed',
          suppression: suppressed?.suppression,
          check: { id: f.checkId, title: f.title, severity: f.severity, remediation: f.remediation },
          controls: f.controls.map((id) => ({ id, ...CONTROLS[id], status: r.controls.find((c) => c.id === id)?.status })),
          source: r.source,
          scannedAt: r.provenance.scannedAt,
          mappingDisclaimer: r.mappingDisclaimer,
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  return server;
}

/* v8 ignore next 5 -- stdio wiring; the server itself is tested over an in-memory transport */
export async function runStdio(opts: { suppressions?: Suppression[] } = {}): Promise<void> {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await createMcpServer(opts).connect(new StdioServerTransport());
  process.stderr.write(`noip mcp: serving ${ALL_CHECKS.length} checks over stdio (read-only)\n`);
}
