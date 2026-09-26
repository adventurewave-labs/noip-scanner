#!/usr/bin/env -S node --no-deprecation
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Command, Option } from 'commander';
import { K8sUnavailable } from './errors.js';
import { explain } from './llm/explain.js';
import { createProvider } from './llm/provider.js';
import { renderMarkdown } from './report/markdown.js';
import { renderSarif } from './report/sarif.js';
import { ingestNetinspect } from './report/netinspect.js';
import { scannerInfo } from './report/provenance.js';
import { buildReport, getSnapshot, isDemoMode } from './scan.js';
import { SEVERITIES, type Severity } from './types.js';

export const EXIT = { OK: 0, ERROR: 1, FINDINGS_AT_THRESHOLD: 2, K8S_UNAVAILABLE: 3 } as const;

interface ScanFlags {
  kubeconfig?: string;
  context?: string;
  output: 'json' | 'md' | 'sarif';
  out?: string;
  explain?: boolean;
  netinspect?: string;
  includeSystem?: boolean;
  excludeNamespace?: string[];
  demo?: boolean;
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
  };
  const { snapshot, source } = await getSnapshot(opts);
  const report = buildReport(snapshot, source, opts);
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
      : JSON.stringify(flags.output === 'sarif' ? renderSarif(report) : report, null, 2) + '\n';
  if (flags.out) writeFileSync(flags.out, body);
  else process.stdout.write(body);

  warn(`${source} scan: ${report.summary.findings} finding(s), score ${report.summary.score}/100${flags.out ? ` -> ${flags.out}` : ''}`);
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
    .addOption(new Option('-o, --output <format>', 'report format').choices(['json', 'md', 'sarif']).default('json'))
    .option('--out <file>', 'write the report to a file instead of stdout')
    .option('--explain', 'add an LLM explanation (redacted input, schema-validated output; needs an API key)')
    .option('--netinspect <file>', 'merge a k8s-netinspect JSON result as a "network" section')
    .option('--include-system', 'also scan kube-system, kube-public and kube-node-lease')
    .option('--exclude-namespace <ns...>', 'additional namespaces to skip')
    .option('--demo', 'scan the bundled demo fixture instead of a cluster (same as NOIP_DEMO=1)')
    .addOption(new Option('--fail-on <severity>', 'exit 2 if any finding is at or above this severity').choices([...SEVERITIES]))
    .action(async (flags: ScanFlags) => {
      process.exitCode = await runScan(flags);
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
