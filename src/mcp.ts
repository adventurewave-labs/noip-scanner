import { realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { ALL_CHECKS } from './checks/index.js';
import { CONTROLS, MAPPING_DISCLAIMER } from './checks/controls.js';
import { scannerInfo } from './report/provenance.js';
import { buildReport, getSnapshot } from './scan.js';
import { SEVERITIES, type Severity } from './types.js';
import type { Suppression } from './suppressions.js';

/**
 * `noip mcp`: expose the deterministic scanner to agents over MCP (stdio).
 * Every tool is read-only and uses the caller's kubeconfig/RBAC. No LLM is involved — the calling agent does the reasoning.
 */

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
/** Talks to the Kubernetes API when not in demo/manifests mode. */
const LIVE_READ_ONLY = { ...READ_ONLY, openWorldHint: true } as const;

// Deliberately no `kubeconfig` argument: a kubeconfig can carry `exec` credential plugins, so letting a tool
// call pick an arbitrary file would let prompt-injected input run commands. The operator fixes it at startup.
const target = {
  context: z.string().optional().describe("Context within the server's kubeconfig. Default: its current context."),
  manifests: z.array(z.string()).optional().describe('Scan these YAML files/directories (relative to the server working directory) offline instead of a cluster.'),
  demo: z.boolean().optional().describe('Scan the bundled fictional demo cluster (source: "demo").'),
  includeSystemNamespaces: z.boolean().optional().describe('Also scan kube-system, kube-public, kube-node-lease.'),
};

type Target = { context?: string; manifests?: string[]; demo?: boolean; includeSystemNamespaces?: boolean };

/** Manifest paths must resolve (after symlinks) inside the server's working directory. */
export function confinePaths(paths: string[], root = process.cwd()): string[] {
  const base = realpathSync(root);
  return paths.map((p) => {
    let real: string;
    try {
      real = realpathSync(resolve(base, p));
    } catch {
      throw Object.assign(new Error(`manifest path not found: ${p}`), { code: 'NotFound' });
    }
    if (real !== base && !real.startsWith(base + sep)) throw Object.assign(new Error(`manifest path outside the working directory: ${p}`), { code: 'Forbidden' });
    return real;
  });
}

const json = (value: unknown): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
  structuredContent: value as Record<string, unknown>,
});
const fail = (err: unknown): CallToolResult => ({
  isError: true,
  content: [{ type: 'text', text: `${(err as { code?: string }).code ?? (err as Error).name}: ${(err as Error).message}` }],
});

export interface McpOptions {
  suppressions?: Suppression[];
  /** Fixed by the operator (`noip mcp --kubeconfig`); tools cannot override it. */
  kubeconfig?: string;
  /** Root that manifest paths are confined to. Default: process.cwd(). */
  root?: string;
}

export function createMcpServer(opts: McpOptions = {}): McpServer {
  const server = new McpServer({ name: 'noip', version: scannerInfo().version });

  async function report(t: Target, minSeverity?: Severity) {
    if (t.manifests?.length && (t.demo || t.context)) throw new Error('manifests cannot be combined with demo or context');
    const scanOpts = {
      ...t,
      manifests: t.manifests?.length ? confinePaths(t.manifests, opts.root) : undefined,
      kubeconfig: opts.kubeconfig,
      suppressions: opts.suppressions,
      minSeverity,
    };
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
      annotations: LIVE_READ_ONLY,
    },
    async (args) => {
      try {
        const { minSeverity, ...t } = args;
        return json(await report(t, minSeverity as Severity | undefined));
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
      annotations: LIVE_READ_ONLY,
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
export async function runStdio(opts: McpOptions = {}): Promise<void> {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  await createMcpServer(opts).connect(new StdioServerTransport());
  process.stderr.write(`noip mcp: serving ${ALL_CHECKS.length} checks over stdio (read-only)\n`);
}
