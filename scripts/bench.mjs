// Quick scale benchmark on a synthetic cluster: node scripts/bench.mjs [namespaces=500] [podsPerNs=20]
import { buildReport } from '../dist/scan.js';
import { renderHtml } from '../dist/report/html.js';
import { renderSarif } from '../dist/report/sarif.js';

const [ns = 500, per = 20] = process.argv.slice(2).map(Number);
const pods = [];
for (let n = 0; n < ns; n++)
  for (let i = 0; i < per; i++)
    pods.push({ metadata: { name: `p-${i}`, namespace: `ns-${n}` }, spec: { hostNetwork: i % 7 === 0, containers: [{ name: 'c', image: 'x', securityContext: i % 2 ? { privileged: true } : {} }] } });
const snapshot = { serverVersion: { gitVersion: 'v1.31.0' }, nodeCount: 0, namespaces: Array.from({ length: ns }, (_, n) => ({ metadata: { name: `ns-${n}` } })), pods, networkPolicies: [], clusterRoleBindings: [], roleBindings: [] };
const t0 = performance.now();
const r = buildReport(snapshot, 'live');
const t1 = performance.now();
renderHtml(r);
renderSarif(r);
const t2 = performance.now();
console.log(`${pods.length} pods / ${ns} namespaces: ${r.findings.length} findings; scan ${(t1 - t0).toFixed(0)} ms, html+sarif ${(t2 - t1).toFixed(0)} ms, heap ${(process.memoryUsage().heapUsed / 1e6).toFixed(0)} MB`);
