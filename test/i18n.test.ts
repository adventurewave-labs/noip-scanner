import { describe, expect, it } from 'vitest';
import { ALL_CHECKS } from '../src/checks/index.js';
import { CONTROLS } from '../src/checks/controls.js';
import { renderHtml } from '../src/report/html.js';
import { STRINGS } from '../src/report/i18n.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';
import { importSarif } from '../src/report/import-sarif.js';
import { ingestNetinspect } from '../src/report/netinspect.js';

const report = () => {
  const r = buildReport(loadDemoSnapshot(), 'demo', {
    suppressions: [{ check: 'NOIP-POD-004', reason: 'agente de nodo necesita la red del host', owner: 'sre', expires: '2099-01-01' }],
  });
  r.imported = importSarif(JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Trivy' } }, results: [{ ruleId: 'X', level: 'error', message: { text: 'm' } }] }] }), 't.sarif');
  r.network = ingestNetinspect(JSON.stringify({ checks: [{ name: 'dns', status: 'pass' }] }));
  r.explanation = null;
  return r;
};

describe('Spanish reports (--lang es)', () => {
  it('translate every check title, remediation and control title', () => {
    const es = STRINGS.es;
    expect(Object.keys(es.checkTitles).sort()).toEqual(ALL_CHECKS.map((c) => c.id).sort());
    expect(Object.keys(es.remediations).sort()).toEqual(ALL_CHECKS.map((c) => c.id).sort());
    expect(Object.keys(es.controlTitles).sort()).toEqual(Object.keys(CONTROLS).sort());
    expect(es.disclaimer).toMatch(/mapeos de referencia, no una certificación/);
  });

  it('render markdown with no English UI left, but untouched evidence and IDs', () => {
    const r = report();
    const md = renderMarkdown(r, 'es');
    for (const s of ['# Reporte de postura NOIP', '## Resumen ejecutivo', 'Corregir primero', '## Hallazgos', '- Evidencia: ', '- Remediación: Quitar securityContext.privileged', '## Suprimidos (riesgo aceptado)', '## Controles', '❌ no cumple', '## Importado: Trivy', '## Red (importado de k8s-netinspect)', 'DATOS DE DEMOSTRACIÓN', 'mapeos de referencia']) {
      expect(md).toContain(s);
    }
    for (const en of ['## Findings', '## Executive summary', 'Remediation:', 'Fix these first', 'DEMO DATA', 'Quick wins', '## Controls', 'Suppressed (accepted risk)']) {
      expect(md).not.toContain(en);
    }
    expect(md).toContain(r.findings[0]!.id);
    expect(md).toContain('spec.containers[shell].securityContext.privileged=true');
  });

  it('render HTML with lang="es" and translated labels', () => {
    const h = renderHtml(report(), 'es');
    expect(h).toContain('<html lang="es">');
    expect(h).toContain('<code>fixtures/demo-cluster.json</code>');
    for (const s of ['Reporte de postura de Kubernetes', 'Resumen ejecutivo', 'Controles con fallas', 'crítico', 'Procedencia', 'no cuenta en el puntaje de NOIP', 'Mejoras rápidas con corrección determinista: <b>']) expect(h).toContain(s);
    expect(h).not.toMatch(/>Findings<|>Executive summary<|>Provenance</);
  });

  it('keeps English output byte-identical to the default', () => {
    const r = report();
    expect(renderMarkdown(r, 'en')).toBe(renderMarkdown(r));
    expect(renderHtml(r, 'en')).toBe(renderHtml(r));
  });

  it('localises the manifests banner and a clean-cluster headline', () => {
    const r = buildReport(loadDemoSnapshot(), 'manifests');
    expect(renderMarkdown(r, 'es')).toContain('ANÁLISIS DE MANIFIESTOS SIN CONEXIÓN');
    expect(renderHtml(r, 'es')).toContain('ANÁLISIS DE MANIFIESTOS SIN CONEXIÓN');
    const clean = buildReport({ ...loadDemoSnapshot(), pods: [], namespaces: [], clusterRoleBindings: [], roleBindings: [], networkPolicies: [] }, 'live');
    expect(renderMarkdown(clean, 'es')).toContain('Sin hallazgos en 15 revisiones. Puntaje 100/100.');
    expect(renderHtml(clean, 'es')).toContain('Sin hallazgos.');
  });
});
