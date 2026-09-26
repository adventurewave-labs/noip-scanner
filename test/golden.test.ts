import { describe, expect, it } from 'vitest';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { golden, snapshotFromMisconfigFixtures } from './helpers.js';

// Offline twin of the CI kind job: the same fixture YAMLs, parsed instead of applied.
describe('golden: seeded misconfigurations (offline)', () => {
  const report = buildReport(snapshotFromMisconfigFixtures(), 'live');
  const inScope = (r: { namespace?: string; name: string }) =>
    r.namespace ? r.namespace.startsWith(golden.scope.namespacePrefix) : r.name.startsWith(golden.scope.clusterScopedNamePrefix);

  it('finds exactly the expected findings', () => {
    expect(report.findings.filter((f) => inScope(f.resource)).map((f) => f.id).sort()).toEqual([...golden.expectedFindingIds].sort());
  });

  it('raises nothing in the clean namespace', () => {
    expect(report.findings.filter((f) => f.resource.namespace === golden.cleanNamespace || f.resource.name === golden.cleanNamespace)).toEqual([]);
  });

  it('fails exactly the expected controls', () => {
    expect(report.controls.filter((c) => c.status === 'fail').map((c) => c.id)).toEqual(golden.expectedFailedControls);
  });

  it('never carries the seeded secret value', () => {
    expect(JSON.stringify(report)).not.toContain(golden.seededSecretValue);
  });
});

describe('golden: demo fixture', () => {
  it('produces a stable finding set', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-01-01T00:00:00Z') });
    expect(r.source).toBe('demo');
    expect({ summary: r.summary, ids: r.findings.map((f) => f.id) }).toMatchSnapshot();
  });
});
