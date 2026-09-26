import { timingSafeEqual, createHash } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { K8sUnavailable, LLMNotConfigured } from '../errors.js';
import { loadKubeConfig } from '../k8s/client.js';
import { probeVersion } from '../k8s/snapshot.js';
import { explain } from '../llm/explain.js';
import type { LLMProvider } from '../llm/provider.js';
import { log } from '../logger.js';
import { renderMarkdown } from '../report/markdown.js';
import { scannerInfo } from '../report/provenance.js';
import { openApiDocument } from './openapi.js';
import { buildReport, getSnapshot, type ScanOptions } from '../scan.js';
import { loadIgnoreFile } from '../suppressions.js';
import type { ClusterSnapshot, DataSource, Report } from '../types.js';
import { METRICS_CONTENT_TYPE, renderMetrics, type ScrapeState } from './metrics.js';

export interface AppDeps {
  /** Bearer token required on every /api/* route. */
  token: string;
  demo: boolean;
  /** Injected for tests; defaults to the real snapshot loader. */
  snapshot?: (opts: ScanOptions & { demo?: boolean }) => Promise<{ snapshot: ClusterSnapshot; source: DataSource }>;
  /** Resolves the LLM provider or throws LLMNotConfigured. */
  provider?: () => Promise<LLMProvider>;
  /** Operator-provided suppressions file (NOIP_IGNORE_FILE). */
  ignoreFile?: string;
  /** Reachability probe for /health; defaults to GET /version against the current kubeconfig. */
  probe?: () => Promise<string>;
  /** How long /api/metrics reuses a successful scan (NOIP_METRICS_TTL, seconds; default 300). */
  metricsTtlSeconds?: number;
  /** Injected clock for tests (ms since epoch). */
  now?: () => number;
}

/** After a failed scan, /api/metrics retries at most this often, so a scrape loop can't hammer a sick API server. */
const METRICS_RETRY_MS = 30_000;

const sha = (s: string) => createHash('sha256').update(s).digest();

export function bearerAuth(token: string) {
  const expected = sha(token);
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.get('authorization') ?? '';
    const m = /^Bearer (.+)$/.exec(header);
    if (m?.[1] && timingSafeEqual(sha(m[1]), expected)) return next();
    res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'Unauthorized', message: 'Missing or invalid bearer token.' });
  };
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export function createApp(deps: AppDeps) {
  const getSnap = deps.snapshot ?? getSnapshot;
  const provider = deps.provider ?? (async () => (await import('../llm/provider.js')).createProvider());
  const probe = deps.probe ?? (async () => probeVersion(loadKubeConfig()));
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '64kb' }));
  if (deps.demo) {
    app.use((_req, res, next) => {
      res.set('X-NOIP-Mode', 'demo');
      next();
    });
  }

  // Suppressions for the API come only from an operator-set file (NOIP_IGNORE_FILE), never from the request.
  const scanOpts = (req: Request): ScanOptions & { demo: boolean } => ({
    demo: deps.demo,
    includeSystemNamespaces: req.query.includeSystem === '1',
    suppressions: deps.ignoreFile ? loadIgnoreFile(deps.ignoreFile) : undefined,
  });

  app.get('/', (_req, res) => {
    if (!deps.demo) return void res.json({ name: 'noip', description: 'Read-only Kubernetes posture scanner', health: '/health', openapi: '/openapi.json', api: '/api (bearer token required)' });
    // Public demo page (Railway preview): fixture data only, clearly labelled. No cluster credentials exist in demo mode.
    getSnap({ demo: true })
      .then(({ snapshot, source }) => {
        const md = renderMarkdown(buildReport(snapshot, source));
        res
          .type('html')
          .send(
            `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NOIP demo report</title>` +
              `<style>body{font:14px/1.5 ui-monospace,monospace;max-width:960px;margin:0 auto;padding:16px;background:#fff;color:#111}` +
              `.banner{background:#fde68a;color:#111;padding:12px 16px;border-radius:6px;font-weight:600}pre{white-space:pre-wrap}` +
              `@media (prefers-color-scheme:dark){body{background:#111;color:#eee}}</style>` +
              `<div class="banner">DEMO MODE — fixture data from fixtures/demo-cluster.json. No live cluster is connected to this preview.</div>` +
              `<pre>${escapeHtml(md)}</pre>`,
          );
      })
      .catch((err: Error) => res.status(500).json({ error: 'Internal', message: err.message }));
  });

  // Public: describing the API reveals nothing about any cluster.
  const spec = openApiDocument();
  app.get('/openapi.json', (_req, res) => void res.json(spec));

  app.get('/health', async (_req, res) => {
    const info = scannerInfo();
    const base = { version: info.version, gitSha: info.gitSha };
    if (deps.demo) return void res.json({ status: 'ok', source: 'demo', kubernetes: 'not-used', ...base });
    try {
      const serverVersion = await probe();
      res.json({ status: 'ok', source: 'live', kubernetes: 'reachable', serverVersion, ...base });
    } catch (err) {
      res.json({ status: 'degraded', source: 'live', kubernetes: 'unreachable', detail: (err as Error).message, ...base });
    }
  });

  const api = express.Router();
  api.use(rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false }));
  api.use(bearerAuth(deps.token));

  api.get('/scan', async (req, res, next) => {
    try {
      const { snapshot, source } = await getSnap(scanOpts(req));
      res.json(buildReport(snapshot, source, scanOpts(req)));
    } catch (err) {
      next(err);
    }
  });

  // Prometheus: cached scan, one scan in flight at a time, failures reported as noip_up 0 with the last good values.
  // Intervals use a monotonic clock, so a wall-clock step can't freeze or bypass the cache.
  const clock = deps.now ?? (() => performance.now());
  const ttlMs = (deps.metricsTtlSeconds ?? 300) * 1000;
  let last: { report: Report; at: number } | undefined;
  let state: ScrapeState = { up: false, failures: 0 };
  let failedAt = -Infinity;
  let inflight: Promise<void> | undefined;
  const refresh = async () => {
    const t0 = clock();
    try {
      const opts = { demo: deps.demo, suppressions: deps.ignoreFile ? loadIgnoreFile(deps.ignoreFile) : undefined };
      const { snapshot, source } = await getSnap(opts);
      last = { report: buildReport(snapshot, source, opts), at: clock() };
      state = { up: true, durationSeconds: (clock() - t0) / 1000, failures: state.failures };
    } catch (err) {
      failedAt = clock(); // back off from when the attempt ended: a slow timeout must not bypass the backoff
      state = { up: false, failures: state.failures + 1 };
      log('warn', `metrics scan failed (${err instanceof K8sUnavailable ? 'K8sUnavailable' : 'Error'}): ${(err as Error).message}`);
    }
  };
  api.get('/metrics', async (_req, res) => {
    if (inflight) await inflight; // concurrent scrapes wait for the scan already running
    else {
      const now = clock();
      const stale = !last || now - last.at >= ttlMs;
      const mayRetry = state.up || now - failedAt >= METRICS_RETRY_MS;
      if (stale && mayRetry) {
        inflight = refresh().finally(() => (inflight = undefined));
        await inflight;
      }
    }
    res.set('Content-Type', METRICS_CONTENT_TYPE).send(renderMetrics(last?.report, state));
  });

  api.get('/discovery/cluster', async (req, res, next) => {
    try {
      const { snapshot: s, source } = await getSnap(scanOpts(req));
      res.json({
        source,
        serverVersion: s.serverVersion.gitVersion,
        platform: s.serverVersion.platform,
        context: s.context,
        nodeCount: s.nodeCount,
        namespaceCount: s.namespaces.length,
        podCount: s.pods.length,
        networkPolicyCount: s.networkPolicies.length,
      });
    } catch (err) {
      next(err);
    }
  });

  api.post('/report/explain', async (req, res, next) => {
    try {
      const llm = await provider(); // throws LLMNotConfigured -> 501, before touching the cluster
      const { snapshot, source } = await getSnap(scanOpts(req));
      const report = buildReport(snapshot, source, scanOpts(req));
      report.explanation = await explain(report, llm, (m) => log('warn', m));
      res.json(report);
    } catch (err) {
      next(err);
    }
  });

  app.use('/api', api);

  // Express 5: no '*' path; a pathless middleware is the catch-all.
  app.use((req, res) => {
    res.status(404).json({ error: 'NotFound', message: `No route for ${req.method} ${req.path}` });
  });

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof K8sUnavailable) return void res.status(503).json({ error: err.code, message: err.message });
    if (err instanceof LLMNotConfigured) return void res.status(501).json({ error: err.code, message: err.message });
    log('error', 'unhandled error', { error: err.message });
    res.status(500).json({ error: 'Internal', message: 'Internal server error' });
  });

  return app;
}
