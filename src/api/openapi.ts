import { readFileSync } from 'node:fs';
import { scannerInfo } from '../report/provenance.js';

/**
 * OpenAPI 3.1 description of the HTTP API. The Report schema is the same JSON Schema (2020-12) that
 * validates CLI output, embedded verbatim, so there is one source of truth. Served at GET /openapi.json.
 */
// src/api/x.ts and dist/api/x.js are both two levels below the package root.
const REPORT_SCHEMA = new URL('../../schemas/report.schema.json', import.meta.url);

export function openApiDocument() {
  const report = JSON.parse(readFileSync(REPORT_SCHEMA, 'utf8')) as Record<string, unknown>;
  delete report.$schema;
  delete report.$id;
  const error = (codes: string[]) => ({
    type: 'object',
    additionalProperties: false,
    required: ['error', 'message'],
    properties: { error: { enum: codes }, message: { type: 'string' } },
  });
  const json = (schema: object, description: string) => ({ description, content: { 'application/json': { schema } } });
  const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
  const includeSystem = { name: 'includeSystem', in: 'query', required: false, schema: { enum: ['1'] }, description: 'Also scan kube-system, kube-public and kube-node-lease.' };
  const common = {
    '401': json(ref('Unauthorized'), 'Missing or invalid bearer token.'),
    '429': { description: 'Rate limited (60 requests/minute).' },
    '503': json(ref('K8sUnavailable'), 'The Kubernetes API is unreachable or refused a read. Never replaced by demo data.'),
  };
  return {
    openapi: '3.1.0',
    info: {
      title: 'NOIP API',
      version: scannerInfo().version,
      description: 'Read-only Kubernetes posture scanner. Findings are deterministic; control mappings are references, not an attestation.',
    },
    jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
    components: {
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer', description: 'NOIP_API_TOKEN' } },
      schemas: {
        Report: report,
        Health: {
          type: 'object',
          required: ['status', 'source', 'kubernetes', 'version', 'gitSha'],
          properties: {
            status: { enum: ['ok', 'degraded'] },
            source: { enum: ['live', 'demo'] },
            kubernetes: { enum: ['reachable', 'unreachable', 'not-used'] },
            serverVersion: { type: 'string' },
            detail: { type: 'string' },
            version: { type: 'string' },
            gitSha: { type: 'string' },
          },
        },
        Cluster: {
          type: 'object',
          additionalProperties: false,
          required: ['source', 'serverVersion', 'nodeCount', 'namespaceCount', 'podCount', 'networkPolicyCount'],
          properties: {
            source: { enum: ['live', 'demo'] },
            serverVersion: { type: 'string' },
            platform: { type: 'string' },
            context: { type: 'string' },
            nodeCount: { type: 'integer', minimum: 0 },
            namespaceCount: { type: 'integer', minimum: 0 },
            podCount: { type: 'integer', minimum: 0 },
            networkPolicyCount: { type: 'integer', minimum: 0 },
          },
        },
        Unauthorized: error(['Unauthorized']),
        K8sUnavailable: error(['K8sUnavailable']),
        LLMNotConfigured: error(['LLMNotConfigured']),
        NotFound: error(['NotFound']),
      },
    },
    paths: {
      '/health': {
        get: {
          operationId: 'health',
          summary: 'Liveness plus Kubernetes reachability. Reports degraded, never healthy, when the cluster is unreachable.',
          security: [],
          responses: { '200': json(ref('Health'), 'Always 200; check `status`.') },
        },
      },
      '/openapi.json': {
        get: { operationId: 'openapi', summary: 'This document.', security: [], responses: { '200': { description: 'OpenAPI 3.1 document.' } } },
      },
      '/api/scan': {
        get: {
          operationId: 'scan',
          summary: 'Run all checks and return the report.',
          security: [{ bearer: [] }],
          parameters: [includeSystem],
          responses: { '200': json(ref('Report'), 'The posture report.'), ...common },
        },
      },
      '/api/discovery/cluster': {
        get: {
          operationId: 'discoverCluster',
          summary: 'Cluster facts: version, node/namespace/pod/NetworkPolicy counts.',
          security: [{ bearer: [] }],
          responses: { '200': json(ref('Cluster'), 'Cluster facts.'), ...common },
        },
      },
      '/api/metrics': {
        get: {
          operationId: 'metrics',
          summary: 'Prometheus metrics for the latest scan (score, findings by severity, failed checks, Pod Security readiness). The scan is cached for NOIP_METRICS_TTL seconds (default 300); a failed scan sets noip_up 0 and keeps the last good values.',
          security: [{ bearer: [] }],
          responses: {
            '200': { description: 'Prometheus text exposition format 0.0.4.', content: { 'text/plain': { schema: { type: 'string' } } } },
            '401': common['401'],
            '429': common['429'],
          },
        },
      },
      '/api/report/explain': {
        post: {
          operationId: 'explain',
          summary: 'Scan, then add a redacted, schema-validated LLM explanation (explanation is null if the model output is rejected).',
          security: [{ bearer: [] }],
          parameters: [includeSystem],
          responses: {
            '200': json(ref('Report'), 'The report with `explanation`.'),
            '501': json(ref('LLMNotConfigured'), 'No LLM provider key configured.'),
            ...common,
          },
        },
      },
    },
  };
}
