#!/usr/bin/env -S node --no-deprecation
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Command, Option } from 'commander';
import { K8sUnavailable } from './errors.js';
import { explain } from './llm/explain.js';
import { createProvider } from './llm/provider.js';
import { diffReports, regressed, renderDiffMarkdown } from './report/diff.js';
import { renderHtml } from './report/html.js';
import { renderMarkdown } from './report/markdown.js';
import { renderSarif } from './report/sarif.js';
import { ingestNetinspect } from './report/netinspect.js';
import { scannerInfo } from './report/provenance.js';
import { buildReport, getSnapshot, isDemoMode } from './scan.js';
import { DEFAULT_IGNORE_FILE, loadIgnoreFile } from './suppressions.js';
import { SEVERITIES, type Report, type Severity } from './types.js';

export const EXIT = { OK: 0, ERROR: 1, FINDINGS_AT_THRESHOLD: 2, K8S_UNAVAILABLE: 3 } as const;

interface ScanFlags {
  kubeconfig?: string;
  context?: string;
  output: 'json' | 'md' | 'sarif' | 'html';
  out?: string;
  explain?: boolean;
  netinspect?: string;
  includeSystem?: boolean;
  excludeNamespace?: string[];
  demo?: boolean;
  manifests?: string[];
  ignoreFile?: string;
  ignore?: boolean;
  minSeverity?: Severity;
  failOn?: Severity;
}

const warn = (m: string) => process.stderr.write(`noip: ${m}\n`);

export async function runScan(flags: ScanFlags): Promise<number> {
  const demo = Boolean(flags.demo) || isDemoMode();
  const opts = {
    kubeconfig: flags.kubeconfig,
    context: flags.context,
    includeSystemNamespaces: flags.includeSystem,
    excludeNamespaces: flags.excludeNamespace,
    demo,
    manifests: flags.manifests,
    minSeverity: flags.minSeverity,
    suppressions: flags.ignore === false ? undefined : loadIgnoreFile(flags.ignoreFile),
  };
  if (flags.manifests?.length && (demo || flags.kubeconfig || flags.context)) {
    throw new Error(`--manifests cannot be combined with ${demo && !flags.demo ? 'NOIP_DEMO' : '--demo'}, --kubeconfig or --context`);
  }
  const { snapshot, source } = await getSnapshot(opts);
  const report = buildReport(snapshot, source, opts);
  for (const w of report.warnings ?? []) warn(`warning: ${w}`);
  if (flags.netinspect) report.network = ingestNetinspect(readFileSync(flags.netinspect, 'utf8'));
  if (flags.explain) {
    try {
      report.explanation = await explain(report, await createProvider(), warn);
    } catch (err) {
      warn((err as Error).message);
      report.explanation = null;
    }
  }

  const body =
    flags.output === 'md'
      ? renderMarkdown(report)
      : flags.output === 'html'
        ? renderHtml(report)
        : JSON.stringify(flags.output === 'sarif' ? renderSarif(report) : report, null, 2) + '\n';
  if (flags.out) writeFileSync(flags.out, body);
  else process.stdout.write(body);

  warn(`${source} scan: ${report.summary.findings} finding(s)${report.summary.suppressed ? ` (+${report.summary.suppressed} suppressed)` : ''}, score ${report.summary.score}/100${flags.out ? ` -> ${flags.out}` : ''}`);
  if (flags.failOn) {
    const limit = SEVERITIES.indexOf(flags.failOn);
    if (report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit)) return EXIT.FINDINGS_AT_THRESHOLD;
  }
  return EXIT.OK;
}

export function buildCli(): Command {
  const program = new Command('noip').description('Read-only Kubernetes posture scanner').version(scannerInfo().version);
  program
    .command('scan')
    .description('Scan the current (or given) kubeconfig context and emit a findings report')
    .option('--kubeconfig <path>', 'kubeconfig file (default: $KUBECONFIG or ~/.kube/config, or in-cluster)')
    .option('--context <name>', 'kubeconfig context to use')
    .addOption(new Option('-o, --output <format>', 'report format').choices(['json', 'md', 'sarif', 'html']).default('json'))
    .option('--out <file>', 'write the report to a file instead of stdout')
    .option('--explain', 'add an LLM explanation (redacted input, schema-validated output; needs an API key)')
    .option('--netinspect <file>', 'merge a k8s-netinspect JSON result as a "network" section')
    .option('--include-system', 'also scan kube-system, kube-public and kube-node-lease')
    .option('--exclude-namespace <ns...>', 'additional namespaces to skip')
    .option('--manifests <paths...>', 'scan YAML files/directories offline instead of a cluster ("-" reads stdin, e.g. helm template … | noip scan --manifests -)')
    .option('--ignore-file <path>', `accepted-risk suppressions with reason/owner/expiry (default: ./${DEFAULT_IGNORE_FILE} if present)`)
    .option('--no-ignore', 'ignore all suppressions and report every finding')
    .option('--demo', 'scan the bundled demo fixture instead of a cluster (same as NOIP_DEMO=1)')
    .addOption(new Option('--min-severity <severity>', 'only report findings at or above this severity (recorded in provenance)').choices([...SEVERITIES]))
    .addOption(new Option('--fail-on <severity>', 'exit 2 if any finding is at or above this severity').choices([...SEVERITIES]))
    .action(async (flags: ScanFlags) => {
      process.exitCode = await runScan(flags);
    });
  program
    .command('diff')
    .description('Show posture drift between two JSON reports (new, resolved, changed findings; control changes; score delta)')
    .argument('<before>', 'earlier report.json')
    .argument('<after>', 'later report.json')
    .addOption(new Option('-o, --output <format>', 'diff format').choices(['md', 'json']).default('md'))
    .addOption(new Option('--fail-on <severity>', 'exit 2 if `after` has a NEW finding at or above this severity').choices([...SEVERITIES]))
    .action((before: string, after: string, flags: { output: 'md' | 'json'; failOn?: Severity }) => {
      const read = (f: string) => {
        const r = JSON.parse(readFileSync(f, 'utf8')) as Report;
        if (r.schemaVersion !== '1' || !Array.isArray(r.findings)) throw new Error(`${f} is not a NOIP report (schemaVersion 1)`);
        return r;
      };
      const d = diffReports(read(before), read(after));
      process.stdout.write(flags.output === 'json' ? JSON.stringify(d, null, 2) + '\n' : renderDiffMarkdown(d));
      warn(`diff: ${d.new.length} new, ${d.resolved.length} resolved, score ${d.scoreDelta >= 0 ? '+' : ''}${d.scoreDelta}`);
      if (flags.failOn && regressed(d, flags.failOn)) process.exitCode = EXIT.FINDINGS_AT_THRESHOLD;
    });

  program
    .command('mcp')
    .description('Serve the scanner to AI agents over MCP (stdio). Tools: scan, list_checks, explain_finding. All read-only.')
    .option('--kubeconfig <path>', 'kubeconfig the server uses (tools cannot choose another file)')
    .option('--ignore-file <path>', `suppressions to apply (default: ./${DEFAULT_IGNORE_FILE} if present)`)
    .option('--no-ignore', 'do not apply suppressions')
    .action(async (flags: { kubeconfig?: string; ignoreFile?: string; ignore?: boolean }) => {
      const { runStdio } = await import('./mcp.js');
      await runStdio({ kubeconfig: flags.kubeconfig, suppressions: flags.ignore === false ? undefined : loadIgnoreFile(flags.ignoreFile) });
    });
  return program;
}

export async function main(argv = process.argv): Promise<void> {
  try {
    await buildCli().parseAsync(argv);
  } catch (err) {
    if (err instanceof K8sUnavailable) {
      warn(`${err.code}: ${err.message}`);
      process.exitCode = EXIT.K8S_UNAVAILABLE;
    } else {
      warn((err as Error).message);
      process.exitCode = EXIT.ERROR;
    }
  }
}

function invokedDirectly(): boolean {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]!) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}
if (invokedDirectly()) await main();
