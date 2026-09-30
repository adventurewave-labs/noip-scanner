import { describe, expect, it } from 'vitest';
import { parseVersion, SUPPORT_TABLE_AS_OF, UPSTREAM, versionSupport } from '../src/k8s/support.js';
import { STRINGS } from '../src/report/i18n.js';
import { renderHtml } from '../src/report/html.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderSarif } from '../src/report/sarif.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const D = (s: string) => new Date(`${s}T12:00:00Z`);

describe('Kubernetes version support facts', () => {
  it('parses vendor-suffixed versions', () => {
    expect(parseVersion('v1.31.4')).toEqual({ minor: '1.31', patch: 4 });
    expect(parseVersion('v1.30.2+k3s1')).toEqual({ minor: '1.30', patch: 2 });
    expect(parseVersion('v1.33.5-eks-113cf36')).toEqual({ minor: '1.33', patch: 5 });
    expect(parseVersion('1.29.0-gke.100')).toEqual({ minor: '1.29', patch: 0 });
    expect(parseVersion('n/a')).toBeUndefined();
  });

  it('classifies supported / ending-soon / end-of-life / unknown and patch lag', () => {
    expect(versionSupport('v1.36.4', D('2026-09-26'))).toMatchObject({ status: 'supported', endOfLife: '2027-06-28', patchBehind: false });
    expect(versionSupport('v1.36.1', D('2026-09-26'))).toMatchObject({ status: 'supported', patchBehind: true, latestPatch: '1.36.4' });
    expect(versionSupport('v1.34.11', D('2026-09-26'))).toMatchObject({ status: 'ending-soon', daysLeft: 31 });
    expect(versionSupport('v1.34.11', D('2026-10-27'))).toMatchObject({ status: 'ending-soon', daysLeft: 0 });
    expect(versionSupport('v1.34.11', D('2026-10-28'))).toMatchObject({ status: 'end-of-life', daysLeft: -1 });
    expect(versionSupport('v1.31.4', D('2026-09-26'))).toMatchObject({ status: 'end-of-life', endOfLife: '2025-11-11', patchBehind: true });
    expect(versionSupport('v1.19.3', D('2026-09-26'))).toMatchObject({ status: 'end-of-life', patchBehind: false });
    expect(versionSupport('v1.99.0', D('2026-09-26'))).toMatchObject({ status: 'unknown' });
    expect(versionSupport('n/a')).toBeUndefined();
  });

  it('table rows are well formed and cite the source date', () => {
    expect(SUPPORT_TABLE_AS_OF).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const [minor, [eol, patch]] of Object.entries(UPSTREAM)) {
      expect(eol).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(patch.startsWith(`${minor}.`)).toBe(true);
    }
  });

  it('is a fact in the report, never a finding, and renders in every format and language', () => {
    const r = buildReport(loadDemoSnapshot(), 'demo', { now: D('2026-09-26') });
    expect(r.provenance.cluster.versionSupport).toMatchObject({ minor: '1.31', status: 'end-of-life' });
    expect(r.summary.score).toBe(buildReport(loadDemoSnapshot(), 'demo').summary.score);
    expect(renderMarkdown(r)).toContain('> ⚠️ Kubernetes 1.31 is past upstream end of life (2025-11-11)');
    expect(renderMarkdown(r, 'es')).toContain('Kubernetes 1.31 ya no tiene soporte upstream');
    expect(renderHtml(r)).toContain('no longer receives security fixes');
    expect(renderSarif(r).runs[0]!.properties!.kubernetesSupport).toMatchObject({ status: 'end-of-life' });
  });

  it('says nothing for a current, fully patched cluster; notes ending-soon and patch-only lag', () => {
    const vs = versionSupport('v1.36.4', D('2026-09-26'))!;
    expect(STRINGS.en.support(vs)).toBeUndefined();
    expect(STRINGS.es.support(vs)).toBeUndefined();
    const soon = versionSupport('v1.34.2', D('2026-09-26'))!;
    expect(STRINGS.en.support(soon)).toMatch(/reaches upstream end of life on 2026-10-27 \(31 days\).*1\.34\.11/);
    expect(STRINGS.es.support(soon)).toMatch(/termina el 2026-10-27 \(31 días\)/);
    const lag = versionSupport('v1.36.1', D('2026-09-26'))!;
    expect(STRINGS.en.support(lag)).toMatch(/patch 1\.36\.4 is available/);
    expect(STRINGS.es.support(lag)).toMatch(/parche 1\.36\.4/);
    const old = versionSupport('v1.19.0', D('2026-09-26'))!;
    expect(STRINGS.en.support(old)).toMatch(/^Kubernetes 1\.19 is past upstream end of life and no longer/);
    expect(STRINGS.es.support(old)).toMatch(/^Kubernetes 1\.19 ya no tiene soporte upstream y no recibe/);
  });
});
