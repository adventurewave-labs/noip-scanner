import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { K8sUnavailable } from '../src/errors.js';
import { renderFleetMarkdown, safeName, scanFleet } from '../src/fleet.js';
import { loadDemoSnapshot } from '../src/scan.js';

const NOW = new Date('2026-09-26T00:00:00Z');
const out = () => join(mkdtempSync(join(tmpdir(), 'noip-fleet-')), 'fleet');

describe('multi-context (fleet) scans', () => {
  it('writes one report per context plus fleet.json/md, and records unreachable clusters without stopping', async () => {
    const dir = out();
    const snap = async (o: { context?: string } = {}) => {
      if (o.context === 'staging') throw new K8sUnavailable('list pods failed: connect ECONNREFUSED');
      const s = loadDemoSnapshot();
      s.context = o.context;
      return { snapshot: s, source: 'live' as const };
    };
    const { fleet, reports } = await scanFleet(['prod/eu-1', 'staging'], { outDir: dir, format: 'json', now: NOW }, snap);
    expect(reports).toHaveLength(1);
    expect(fleet.clusters).toEqual([
      expect.objectContaining({ context: 'prod/eu-1', status: 'ok', file: 'cluster-prod_eu-1.json', score: 12, serverVersion: 'v1.31.4' }),
      { context: 'staging', status: 'unreachable', error: 'list pods failed: connect ECONNREFUSED' },
    ]);
    expect(JSON.parse(readFileSync(join(dir, 'cluster-prod_eu-1.json'), 'utf8')).provenance.cluster.context).toBe('prod/eu-1');
    expect(JSON.parse(readFileSync(join(dir, 'fleet.json'), 'utf8')).generatedAt).toBe('2026-09-26T00:00:00.000Z');
    const md = readFileSync(join(dir, 'fleet.md'), 'utf8');
    expect(md).toContain('1/2 cluster(s) scanned · lowest score: **prod/eu-1** (12/100)');
    expect(md).toContain('| staging | ❌ unreachable |');
  });

  it('writes each chosen format', async () => {
    for (const [format, ext] of [['md', 'md'], ['html', 'html'], ['sarif', 'sarif']] as const) {
      const dir = out();
      await scanFleet(['a'], { outDir: dir, format, now: NOW }, async () => ({ snapshot: loadDemoSnapshot(), source: 'live' }));
      expect(existsSync(join(dir, `cluster-a.${ext}`))).toBe(true);
    }
  });

  it('rethrows non-connectivity errors, rejects empty or colliding context lists', async () => {
    await expect(scanFleet(['a'], { outDir: out(), format: 'json' }, async () => { throw new Error('bug'); })).rejects.toThrow('bug');
    await expect(scanFleet([], { outDir: out(), format: 'json' })).rejects.toThrow(/no contexts/);
    await expect(scanFleet(['a/b', 'a_b'], { outDir: out(), format: 'json' })).rejects.toThrow(/collide/);
    await expect(scanFleet(['Prod', 'prod'], { outDir: out(), format: 'json' })).rejects.toThrow(/collide/);
  });

  it('sanitises context names into safe file names', () => {
    expect(safeName('arn:aws:eks:us-east-1:123:cluster/prod')).toBe('cluster-arn_aws_eks_us-east-1_123_cluster_prod');
    expect(safeName('../x')).toBe('cluster-.._x');
    expect(safeName('fleet')).toBe('cluster-fleet'); // can never overwrite fleet.json / fleet.md
  });

  it('renders an all-unreachable fleet', () => {
    expect(renderFleetMarkdown({ generatedAt: 'now', clusters: [{ context: 'x', status: 'unreachable', error: 'a|b' }] })).toContain('a\\|b');
  });
});
