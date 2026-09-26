#!/usr/bin/env -S node --no-deprecation
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Command, Option } from 'commander';
import { K8sUnavailable } from './errors.js';
import { explain } from './llm/explain.js';
import { createProvider } from './llm/provider.js';
import { verifyBundle, writeBundle } from './report/bundle.js';
import { diffReports, regressed, renderDiffMarkdown } from './report/diff.js';
import { renderHtml } from './report/html.js';
import { LANGS, type Lang } from './report/i18n.js';
import { importSarif } from './report/import-sarif.js';
import { renderMarkdown } from './report/markdown.js';
import { renderSarif } from './report/sarif.js';
import { ingestNetinspect } from './report/netinspect.js';
import { scannerInfo } from './report/provenance.js';
import { buildReport, getSnapshot, isDemoMode } from './scan.js';
import { DEFAULT_IGNORE_FILE, loadIgnoreFile } from './suppressions.js';
import { SEVERITIES, type Report, type Severity } from './types.js';

export const EXIT = { OK: 0, ERROR: 1, FINDINGS_AT_THRESHOLD: 2, K8S_UNAVAILABLE: 3, VERIFY_FAILED: 4 } as const;

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
  bundle?: string;
  importSarif?: string[];
  contexts?: string[];
  allContexts?: boolean;
  outDir?: string;
  lang?: Lang;
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
  if (flags.manifests?.length && (demo || flags.kubeconfig || flags.context || flags.contexts?.length || flags.allContexts)) {
    throw new Error(`--manifests cannot be combined with ${demo && !flags.demo ? 'NOIP_DEMO' : '--demo'}, --kubeconfig, --context, --contexts or --all-contexts`);
  }
  if (flags.contexts?.length || flags.allContexts) return runFleet(flags, opts);
  const { snapshot, source } = await getSnapshot(opts);
  const report = buildReport(snapshot, source, opts);
  for (const w of report.warnings ?? []) warn(`warning: ${w}`);
  if (flags.netinspect) report.network = ingestNetinspect(readFileSync(flags.netinspect, 'utf8'));
  if (flags.importSarif?.length) report.imported = flags.importSarif.flatMap((f) => importSarif(readFileSync(f, 'utf8'), f));
  if (flags.explain) {
    try {
      report.explanation = await explain(report, await createProvider(), warn);
    } catch (err) {
      warn((err as Error).message);
      report.explanation = null;
    }
  }

  if (flags.bundle) {
    writeBundle(flags.bundle, report, flags.lang);
    warn(`evidence bundle written to ${flags.bundle} (verify: noip verify-bundle ${flags.bundle}  or  sha256sum -c SHA256SUMS)`);
  }
  const body =
    flags.output === 'md'
      ? renderMarkdown(report, flags.lang)
      : flags.output === 'html'
        ? renderHtml(report, flags.lang)
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

async function runFleet(flags: ScanFlags, opts: Parameters<typeof buildReport>[2] & { kubeconfig?: string; demo?: boolean; manifests?: string[] }): Promise<number> {
  if (flags.context || opts.demo || opts.manifests?.length) throw new Error('--contexts/--all-contexts cannot be combined with --context, --demo or --manifests');
  if (!flags.outDir) throw new Error('--contexts/--all-contexts need --out-dir <dir> (one report per cluster + fleet.json/fleet.md)');
  if (flags.out || flags.bundle || flags.explain || flags.netinspect || flags.importSarif?.length) {
    throw new Error('--out, --bundle, --explain, --netinspect and --import-sarif apply to a single cluster; run them per context');
  }
  const { allContexts, scanFleet } = await import('./fleet.js');
  const contexts = flags.allContexts ? allContexts(opts.kubeconfig) : flags.contexts!;
  const { fleet, reports } = await scanFleet(contexts, { ...opts, outDir: flags.outDir, format: flags.output, lang: flags.lang });
  for (const c of fleet.clusters) warn(c.status === 'ok' ? `${c.context}: ${c.findings} finding(s), score ${c.score}/100` : `${c.context}: UNREACHABLE (${c.error})`);
  warn(`fleet: ${fleet.clusters.filter((c) => c.status === 'ok').length}/${fleet.clusters.length} cluster(s) scanned -> ${flags.outDir}/fleet.md`);
  if (fleet.clusters.some((c) => c.status === 'unreachable')) return EXIT.K8S_UNAVAILABLE;
  if (flags.failOn) {
    const limit = SEVERITIES.indexOf(flags.failOn);
    if (reports.some((r) => r.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit))) return EXIT.FINDINGS_AT_THRESHOLD;
  }
  return EXIT.OK;
}

function readReport(f: string): Report {
  const r = JSON.parse(readFileSync(f, 'utf8')) as Report;
  if (r?.schemaVersion !== '1' || !Array.isArray(r.findings)) throw new Error(`${f} is not a NOIP report (schemaVersion 1)`);
  return r;
}

export function buildCli(): Command {
  const program = new Command('noip').description('Read-only Kubernetes posture scanner').version(scannerInfo().version);
  program
    .command('scan')
    .description('Scan the current (or given) kubeconfig context and emit a findings report; with paths, scan YAML offline')
    .argument('[paths...]', 'YAML files or directories to scan offline (same as --manifests)')
    .option('--kubeconfig <path>', 'kubeconfig file (default: $KUBECONFIG or ~/.kube/config, or in-cluster)')
    .option('--context <name>', 'kubeconfig context to use')
    .option('--contexts <names...>', 'scan several contexts (one report each + fleet summary; needs --out-dir)')
    .option('--all-contexts', 'scan every context in the kubeconfig (needs --out-dir)')
    .option('--out-dir <dir>', 'output directory for multi-context scans')
    .addOption(new Option('-o, --output <format>', 'report format').choices(['json', 'md', 'sarif', 'html']).default('json'))
    .option('--out <file>', 'write the report to a file instead of stdout')
    .addOption(new Option('--lang <lang>', 'language for md/html reports (JSON and SARIF stay English)').choices([...LANGS]).default('en'))
    .option('--explain', 'add an LLM explanation (redacted input, schema-validated output; needs an API key)')
    .option('--import-sarif <files...>', "merge other scanners' SARIF (Trivy, kubescape, Checkov…) as imported results; never changes NOIP's score")
    .option('--netinspect <file>', 'merge a k8s-netinspect JSON result as a "network" section')
    .option('--include-system', 'also scan kube-system, kube-public and kube-node-lease')
    .option('--exclude-namespace <ns...>', 'additional namespaces to skip')
    .option('--manifests <paths...>', 'scan YAML files/directories offline instead of a cluster ("-" reads stdin, e.g. helm template … | noip scan --manifests -)')
    .option('--bundle <dir>', 'also write an audit evidence bundle: json/md/html/sarif + SHA256SUMS + in-toto statement')
    .option('--ignore-file <path>', `accepted-risk suppressions with reason/owner/expiry (default: ./${DEFAULT_IGNORE_FILE} if present)`)
    .option('--no-ignore', 'ignore all suppressions and report every finding')
    .option('--demo', 'scan the bundled demo fixture instead of a cluster (same as NOIP_DEMO=1)')
    .addOption(new Option('--min-severity <severity>', 'only report findings at or above this severity (recorded in provenance)').choices([...SEVERITIES]))
    .addOption(new Option('--fail-on <severity>', 'exit 2 if any finding is at or above this severity').choices([...SEVERITIES]))
    .action(async (paths: string[], flags: ScanFlags) => {
      process.exitCode = await runScan(paths.length ? { ...flags, manifests: [...(flags.manifests ?? []), ...paths] } : flags);
    });
  program
    .command('render')
    .description('Render a saved JSON report as markdown, HTML or SARIF (no rescan, so every format shows the same snapshot)')
    .argument('<report>', 'report.json written by `noip scan`')
    .addOption(new Option('-o, --output <format>', 'format').choices(['md', 'html', 'sarif']).default('md'))
    .addOption(new Option('--lang <lang>', 'language for md/html').choices([...LANGS]).default('en'))
    .option('--out <file>', 'write to a file instead of stdout')
    .action((file: string, flags: { output: 'md' | 'html' | 'sarif'; lang: Lang; out?: string }) => {
      const r = readReport(file);
      const body = flags.output === 'sarif' ? JSON.stringify(renderSarif(r), null, 2) + '\n' : flags.output === 'html' ? renderHtml(r, flags.lang) : renderMarkdown(r, flags.lang);
      if (flags.out) writeFileSync(flags.out, body);
      else process.stdout.write(body);
    });

  program
    .command('diff')
    .description('Show posture drift between two JSON reports (new, resolved, changed findings; control changes; score delta)')
    .argument('<before>', 'earlier report.json')
    .argument('<after>', 'later report.json')
    .addOption(new Option('-o, --output <format>', 'diff format').choices(['md', 'json']).default('md'))
    .addOption(new Option('--fail-on <severity>', 'exit 2 if `after` has a NEW finding at or above this severity').choices([...SEVERITIES]))
    .action((before: string, after: string, flags: { output: 'md' | 'json'; failOn?: Severity }) => {
      const d = diffReports(readReport(before), readReport(after));
      process.stdout.write(flags.output === 'json' ? JSON.stringify(d, null, 2) + '\n' : renderDiffMarkdown(d));
      warn(`diff: ${d.new.length} new, ${d.resolved.length} resolved, score ${d.scoreDelta >= 0 ? '+' : ''}${d.scoreDelta}`);
      if (flags.failOn && regressed(d, flags.failOn)) process.exitCode = EXIT.FINDINGS_AT_THRESHOLD;
    });

  program
    .command('history')
    .description('Show the posture score trend across saved JSON reports (per target; HTML includes a chart)')
    .argument('<paths...>', 'report.json files or directories containing them')
    .addOption(new Option('-o, --output <format>', 'history format').choices(['md', 'html', 'json']).default('md'))
    .addOption(new Option('--lang <lang>', 'language for md/html').choices([...LANGS]).default('en'))
    .option('--out <file>', 'write to a file instead of stdout')
    .action(async (paths: string[], flags: { output: 'md' | 'html' | 'json'; lang: Lang; out?: string }) => {
      const { loadHistory, renderHistoryHtml, renderHistoryMarkdown } = await import('./report/history.js');
      const h = loadHistory(paths);
      const body = flags.output === 'json' ? JSON.stringify(h, null, 2) + '\n' : flags.output === 'html' ? renderHistoryHtml(h, flags.lang) : renderHistoryMarkdown(h, flags.lang);
      if (flags.out) writeFileSync(flags.out, body);
      else process.stdout.write(body);
      const n = h.targets.reduce((a, t) => a + t.points.length, 0);
      warn(`history: ${n} report(s) across ${h.targets.length} target(s)${h.skipped.length ? `, ${h.skipped.length} file(s) skipped` : ''}`);
      if (!n) process.exitCode = EXIT.ERROR;
    });

  program
    .command('policy')
    .description('Print ValidatingAdmissionPolicy YAML (CEL) mirroring the pod and namespace checks. Prints only; applies nothing.')
    .addOption(new Option('--action <action>', 'binding action: warn (Warn+Audit), audit, or deny').choices(['warn', 'audit', 'deny']).default('warn'))
    .option('--checks <ids...>', 'only these check IDs (default: every admission-shaped check)')
    .addOption(new Option('--min-severity <severity>', 'only checks at or above this severity').choices([...SEVERITIES]))
    .option('--include-system', 'also apply to kube-system, kube-public and kube-node-lease')
    .option('--exclude-namespace <ns...>', 'additional namespaces the policies skip')
    .option('--out <file>', 'write to a file instead of stdout')
    .action(async (flags: { action: 'warn' | 'audit' | 'deny'; checks?: string[]; minSeverity?: Severity; includeSystem?: boolean; excludeNamespace?: string[]; out?: string }) => {
      const { policyDocuments, renderPolicies } = await import('./policy.js');
      const opts = { action: flags.action, checks: flags.checks, minSeverity: flags.minSeverity, includeSystemNamespaces: flags.includeSystem, excludeNamespaces: flags.excludeNamespace };
      const yaml = renderPolicies(opts);
      if (flags.out) writeFileSync(flags.out, yaml);
      else process.stdout.write(yaml);
      warn(`policy: ${policyDocuments(opts).length / 2} ValidatingAdmissionPolicy + binding pair(s), action ${flags.action}`);
    });

  program
    .command('fix')
    .description('Apply deterministic fixes from a manifest scan back onto the YAML (comments preserved)')
    .argument('<paths...>', 'YAML files or directories')
    .option('--out-dir <dir>', 'write patched copies here (mirrors relative paths)')
    .option('--in-place', 'overwrite the input files')
    .option('--ignore-file <path>', 'suppressions to honour (suppressed findings are not fixed)')
    .option('--no-ignore', 'ignore suppressions')
    .action(async (paths: string[], flags: { outDir?: string; inPlace?: boolean; ignoreFile?: string; ignore?: boolean }) => {
      const { fixManifests } = await import('./fix.js');
      const r = await fixManifests(paths, { ...flags, suppressions: flags.ignore === false ? undefined : loadIgnoreFile(flags.ignoreFile) });
      for (const a of r.applied) warn(`fixed ${a.findingId} (${a.file}): ${a.description}`);
      for (const f of r.advisory) warn(`needs a human: ${f.id} — ${f.remediation}`);
      warn(`${r.applied.length} fix(es) applied to ${r.filesWritten.length} file(s); ${r.advisory.length} finding(s) left for review`);
    });

  program
    .command('verify-bundle')
    .description('Verify an evidence bundle: file hashes, in-toto subjects and report provenance')
    .argument('<dir>', 'bundle directory written by `noip scan --bundle`')
    .action((dir: string) => {
      const v = verifyBundle(dir);
      if (v.ok) warn(`bundle OK: ${v.files} files verified`);
      else {
        for (const p of v.problems) warn(`bundle FAIL: ${p}`);
        process.exitCode = EXIT.VERIFY_FAILED;
      }
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
