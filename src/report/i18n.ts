import type { Severity } from '../types.js';

/**
 * Report localisation. The JSON report stays canonical English (IDs, evidence, schema); only the
 * human-readable renderers (markdown, HTML) are translated. Evidence lines stay as-is: they quote
 * Kubernetes field paths, which are English in every cluster.
 */
export type Lang = 'en' | 'es';
export const LANGS: readonly Lang[] = ['en', 'es'];

type Scope = 'cluster' | 'namespace' | 'workload';

export interface Strings {
  title: string;
  htmlTitle: string;
  demoBanner: string;
  manifestsBanner: string;
  source: string;
  scannedAt: string;
  cluster: string;
  scanner: string;
  checksRun: string;
  excluded: string;
  none: string;
  nodes: (n: number) => string;
  summary: string;
  score: string;
  findingsN: (n: number) => string;
  sev: Record<Severity, string>;
  checksFailed: (a: number, b: number) => string;
  controlsFailed: (a: number, b: number) => string;
  suppressedN: (n: number) => string;
  executive: string;
  headlineClean: (checks: number, score: number) => string;
  headline: (score: number, findings: number, crit: number, high: number, failed: number, checks: number, quick: number) => string;
  fixFirst: string;
  priorityLine: (sev: Severity, scope: Scope, resources: number, autoFixable: number) => string;
  eg: string;
  quickWins: (q: number, d: number) => [string, string];
  explanation: string;
  explanationMissing: string;
  fix: string;
  findings: string;
  noFindings: string;
  resource: string;
  evidence: string;
  remediation: string;
  controls: string;
  references: string;
  findingId: string;
  suppressedTitle: string;
  suppressedCols: [string, string, string, string];
  warnings: string;
  controlsCols: [string, string, string, string, string, string];
  pass: string;
  fail: string;
  imported: string;
  importedFrom: (file: string, sha: string) => string;
  noResults: string;
  importedCols: [string, string, string, string];
  network: string;
  networkCols: [string, string, string];
  networkNote: string;
  unknown: string;
  checkTitles: Record<string, string>;
  remediations: Record<string, string>;
  controlTitles: Record<string, string>;
  disclaimer: string;
  provenance: string;
  minSeverity: string;
  check: string;
  controlsFailedTile: string;
  notInScore: string;
  support: (vs: import('../k8s/support.js').VersionSupport) => string | undefined;
}

const EN: Strings = {
  title: 'NOIP posture report',
  htmlTitle: 'Kubernetes posture report',
  demoBanner: 'DEMO DATA. This report was generated from the bundled fixture `fixtures/demo-cluster.json`, not a live cluster.',
  manifestsBanner: 'OFFLINE MANIFEST SCAN. Findings describe the YAML as written, not what is running. Namespace-level checks only see Namespace objects present in the input.',
  source: 'Source',
  scannedAt: 'Scanned at',
  cluster: 'Cluster',
  scanner: 'Scanner',
  checksRun: 'Checks run',
  excluded: 'Excluded namespaces',
  none: 'none',
  nodes: (n) => `${n} node(s)`,
  summary: 'Summary',
  score: 'Score',
  findingsN: (n) => `${n} finding(s)`,
  sev: { critical: 'critical', high: 'high', medium: 'medium', low: 'low' },
  checksFailed: (a, b) => `${a}/${b} checks failed`,
  controlsFailed: (a, b) => `${a}/${b} controls failed`,
  suppressedN: (n) => `${n} suppressed (accepted risk, listed below)`,
  executive: 'Executive summary',
  headlineClean: (checks, score) => `No findings across ${checks} checks. Score ${score}/100.`,
  headline: (score, findings, crit, high, failed, checks, quick) =>
    `Score ${score}/100. ${findings} finding(s) (${crit} critical, ${high} high) from ${failed} of ${checks} checks; ${quick} have a deterministic fix.`,
  fixFirst: 'Fix these first (deterministic ranking: severity, then blast radius, then reach):',
  priorityLine: (sev, scope, n, auto) => `${sev}, ${scope}-scoped, ${n} resource(s)${auto ? `, ${auto} auto-fixable` : ''}`,
  eg: 'e.g.',
  quickWins: (q, d) => [`Quick wins with a deterministic fix: **${q}**`, `need a design decision: **${d}**`],
  explanation: 'Explanation (LLM-generated, advisory)',
  explanationMissing: 'LLM explanation requested but unavailable or rejected by schema validation; deterministic findings below are unaffected.',
  fix: 'Fix:',
  findings: 'Findings',
  noFindings: 'No findings.',
  resource: 'Resource',
  evidence: 'Evidence',
  remediation: 'Remediation',
  controls: 'Controls',
  references: 'References',
  findingId: 'Finding ID',
  suppressedTitle: 'Suppressed (accepted risk)',
  suppressedCols: ['Finding', 'Reason', 'Owner', 'Expires'],
  warnings: 'Warnings',
  controlsCols: ['Control', 'Title', 'Status', 'Findings', 'SOC 2 (ref)', 'HIPAA (ref)'],
  pass: 'pass',
  fail: 'fail',
  imported: 'Imported',
  importedFrom: (file, sha) => `From ${file} (sha256 \`${sha}…\`). Not included in NOIP's score or control status.`,
  noResults: 'No results.',
  importedCols: ['Severity', 'Rule', 'Location', 'Message'],
  network: 'Network (ingested from k8s-netinspect)',
  networkCols: ['Check', 'Status', 'Detail'],
  networkNote: 'NOIP does not diagnose the network itself; this section is reproduced from the input file.',
  unknown: 'unknown',
  checkTitles: {},
  remediations: {},
  controlTitles: {},
  disclaimer: '',
  provenance: 'Provenance',
  minSeverity: 'Minimum severity',
  check: 'Check',
  controlsFailedTile: 'Controls failed',
  notInScore: "not in NOIP's score",
  support: (v) => {
    const tail = ` (upstream schedule from kubernetes.io as of ${v.asOf}; managed platforms such as EKS, GKE and AKS publish their own).`;
    const patch = v.patchBehind ? ` A newer patch, ${v.latestPatch}, exists.` : '';
    if (v.status === 'end-of-life') return `Kubernetes ${v.minor} is past upstream end of life${v.endOfLife ? ` (${v.endOfLife})` : ''} and no longer receives security fixes${tail}${patch}`;
    if (v.status === 'ending-soon') return `Kubernetes ${v.minor} reaches upstream end of life on ${v.endOfLife} (${v.daysLeft} days)${tail}${patch}`;
    if (v.status === 'supported' && v.patchBehind) return `Kubernetes ${v.minor} is supported upstream until ${v.endOfLife}; patch ${v.latestPatch} is available${tail}`;
    return undefined;
  },
};

const SEV_ES: Record<Severity, string> = { critical: 'crítico', high: 'alto', medium: 'medio', low: 'bajo' };
const SCOPE_ES: Record<Scope, string> = { cluster: 'todo el clúster', namespace: 'un namespace', workload: 'una carga de trabajo' };

const ES: Strings = {
  title: 'Reporte de postura NOIP',
  htmlTitle: 'Reporte de postura de Kubernetes',
  demoBanner: 'DATOS DE DEMOSTRACIÓN. Este reporte se generó con el fixture incluido `fixtures/demo-cluster.json`, no con un clúster real.',
  manifestsBanner: 'ANÁLISIS DE MANIFIESTOS SIN CONEXIÓN. Los hallazgos describen el YAML tal como está escrito, no lo que se está ejecutando. Las revisiones a nivel de namespace solo consideran los objetos Namespace incluidos.',
  source: 'Origen',
  scannedAt: 'Fecha del análisis',
  cluster: 'Clúster',
  scanner: 'Escáner',
  checksRun: 'Revisiones ejecutadas',
  excluded: 'Namespaces excluidos',
  none: 'ninguno',
  nodes: (n) => `${n} nodo(s)`,
  summary: 'Resumen',
  score: 'Puntaje',
  findingsN: (n) => `${n} hallazgo(s)`,
  sev: SEV_ES,
  checksFailed: (a, b) => `${a}/${b} revisiones con fallas`,
  controlsFailed: (a, b) => `${a}/${b} controles con fallas`,
  suppressedN: (n) => `${n} suprimido(s) (riesgo aceptado, ver abajo)`,
  executive: 'Resumen ejecutivo',
  headlineClean: (checks, score) => `Sin hallazgos en ${checks} revisiones. Puntaje ${score}/100.`,
  headline: (score, findings, crit, high, failed, checks, quick) =>
    `Puntaje ${score}/100. ${findings} hallazgo(s) (${crit} críticos, ${high} altos) en ${failed} de ${checks} revisiones; ${quick} tienen una corrección determinista.`,
  fixFirst: 'Corregir primero (orden determinista: severidad, luego alcance, luego número de recursos):',
  priorityLine: (sev, scope, n, auto) => `${SEV_ES[sev]}, afecta ${SCOPE_ES[scope]}, ${n} recurso(s)${auto ? `, ${auto} con corrección automática` : ''}`,
  eg: 'p. ej.',
  quickWins: (q, d) => [`Mejoras rápidas con corrección determinista: **${q}**`, `requieren una decisión de diseño: **${d}**`],
  explanation: 'Explicación (generada por IA, orientativa)',
  explanationMissing: 'Se solicitó una explicación de IA, pero no estuvo disponible o no pasó la validación del esquema; los hallazgos deterministas no se ven afectados.',
  fix: 'Corrección:',
  findings: 'Hallazgos',
  noFindings: 'Sin hallazgos.',
  resource: 'Recurso',
  evidence: 'Evidencia',
  remediation: 'Remediación',
  controls: 'Controles',
  references: 'Referencias',
  findingId: 'ID del hallazgo',
  suppressedTitle: 'Suprimidos (riesgo aceptado)',
  suppressedCols: ['Hallazgo', 'Motivo', 'Responsable', 'Vence'],
  warnings: 'Advertencias',
  controlsCols: ['Control', 'Título', 'Estado', 'Hallazgos', 'SOC 2 (ref.)', 'HIPAA (ref.)'],
  pass: 'cumple',
  fail: 'no cumple',
  imported: 'Importado',
  importedFrom: (file, sha) => `Desde ${file} (sha256 \`${sha}…\`). No se incluye en el puntaje ni en el estado de los controles de NOIP.`,
  noResults: 'Sin resultados.',
  importedCols: ['Severidad', 'Regla', 'Ubicación', 'Mensaje'],
  network: 'Red (importado de k8s-netinspect)',
  networkCols: ['Revisión', 'Estado', 'Detalle'],
  networkNote: 'NOIP no diagnostica la red; esta sección se reproduce del archivo de entrada.',
  unknown: 'desconocido',
  checkTitles: {
    'NOIP-POD-001': 'Contenedor privilegiado',
    'NOIP-POD-002': 'El pod comparte el espacio de PID del host',
    'NOIP-POD-003': 'El pod comparte el espacio IPC del host',
    'NOIP-POD-004': 'El pod usa la red del host',
    'NOIP-POD-005': 'Escalamiento de privilegios no deshabilitado',
    'NOIP-POD-006': 'El contenedor podría ejecutarse como root',
    'NOIP-POD-007': 'Sistema de archivos raíz con escritura',
    'NOIP-POD-008': 'Falta el límite de CPU o memoria',
    'NOIP-POD-009': 'Secreto expuesto como variable de entorno',
    'NOIP-NS-001': 'Pod Security Admission no aplica baseline ni restricted',
    'NOIP-NET-001': 'Namespace sin NetworkPolicy',
    'NOIP-NET-002': 'NetworkPolicy permite salida a cualquier destino',
    'NOIP-RBAC-001': 'cluster-admin otorgado a un grupo amplio o a usuarios anónimos',
    'NOIP-RBAC-002': 'cluster-admin otorgado a una ServiceAccount default',
    'NOIP-RBAC-003': 'Rol asignado a una ServiceAccount default',
  },
  remediations: {
    'NOIP-POD-001': 'Quitar securityContext.privileged: true; otorgar solo las capacidades de Linux específicas que se necesiten.',
    'NOIP-POD-002': 'Quitar hostPID: true de la especificación del pod.',
    'NOIP-POD-003': 'Quitar hostIPC: true de la especificación del pod.',
    'NOIP-POD-004': 'Quitar hostNetwork: true, salvo que la carga sea un agente de nodo que realmente lo necesite.',
    'NOIP-POD-005': 'Establecer securityContext.allowPrivilegeEscalation: false en cada contenedor.',
    'NOIP-POD-006': 'Establecer runAsNonRoot: true (en el securityContext del pod o del contenedor) y un runAsUser distinto de cero.',
    'NOIP-POD-007': 'Establecer securityContext.readOnlyRootFilesystem: true y montar volúmenes emptyDir para las rutas que requieran escritura.',
    'NOIP-POD-008': 'Definir resources.limits.cpu y resources.limits.memory.',
    'NOIP-POD-009': 'Montar el secreto como volumen de solo lectura en lugar de env.valueFrom.secretKeyRef / envFrom.secretRef.',
    'NOIP-NS-001': 'Etiquetar el namespace con pod-security.kubernetes.io/enforce=restricted (o baseline si restricted aún no es viable), después de una prueba con pod-security.kubernetes.io/warn.',
    'NOIP-NET-001': 'Agregar una NetworkPolicy de denegación por defecto (entrada y salida) y reglas explícitas de permiso.',
    'NOIP-NET-002': 'Dar a cada regla de salida un `to` explícito (namespaceSelector/podSelector/ipBlock) y puertos.',
    'NOIP-RBAC-001': 'Eliminar el binding; otorgar roles de mínimo privilegio a sujetos específicos.',
    'NOIP-RBAC-002': 'Crear una ServiceAccount dedicada con un rol de mínimo privilegio; nunca asignar cluster-admin a `default`.',
    'NOIP-RBAC-003': 'Asignar el rol a una ServiceAccount con nombre y dejar `default` sin permisos.',
  },
  controlTitles: {
    'CIS-5.1.1': 'El rol cluster-admin se usa solo donde es necesario',
    'CIS-5.1.5': 'Las ServiceAccount default no se usan activamente',
    'CIS-5.2.1': 'Minimizar la admisión de contenedores privilegiados',
    'CIS-5.2.2': 'Minimizar contenedores que comparten el espacio de PID del host',
    'CIS-5.2.3': 'Minimizar contenedores que comparten el espacio IPC del host',
    'CIS-5.2.4': 'Minimizar contenedores que comparten la red del host',
    'CIS-5.2.5': 'Minimizar contenedores con allowPrivilegeEscalation',
    'CIS-5.2.6': 'Minimizar la admisión de contenedores root',
    'CIS-5.3.2': 'Todos los namespaces tienen NetworkPolicies definidas',
    'CIS-5.4.1': 'Preferir secretos como archivos en lugar de variables de entorno',
  },
  disclaimer:
    'Los identificadores de SOC 2, HIPAA, NSA/CISA y NIST SP 800-190 son mapeos de referencia, no una certificación. NOIP revisa un subconjunto de cargas de trabajo del CIS Kubernetes Benchmark nivel 1 y no evalúa controles del plano de control, de nodos ni de procesos.',
  provenance: 'Procedencia',
  minSeverity: 'Severidad mínima',
  check: 'Revisión',
  controlsFailedTile: 'Controles con fallas',
  notInScore: 'no cuenta en el puntaje de NOIP',
  support: (v) => {
    const tail = ` (calendario upstream de kubernetes.io al ${v.asOf}; las plataformas administradas como EKS, GKE y AKS publican el suyo).`;
    const patch = v.patchBehind ? ` Existe un parche más reciente: ${v.latestPatch}.` : '';
    if (v.status === 'end-of-life') return `Kubernetes ${v.minor} ya no tiene soporte upstream${v.endOfLife ? ` (fin de vida: ${v.endOfLife})` : ''} y no recibe correcciones de seguridad${tail}${patch}`;
    if (v.status === 'ending-soon') return `El soporte upstream de Kubernetes ${v.minor} termina el ${v.endOfLife} (${v.daysLeft} días)${tail}${patch}`;
    if (v.status === 'supported' && v.patchBehind) return `Kubernetes ${v.minor} tiene soporte upstream hasta el ${v.endOfLife}; está disponible el parche ${v.latestPatch}${tail}`;
    return undefined;
  },
};

export const STRINGS: Record<Lang, Strings> = { en: EN, es: ES };

/** Localised check title / remediation / control title, falling back to the report's English text. */
export const localise = (t: Strings) => ({
  title: (checkId: string, fallback: string) => t.checkTitles[checkId] ?? fallback,
  remediation: (checkId: string, fallback: string) => t.remediations[checkId] ?? fallback,
  control: (id: string, fallback: string) => t.controlTitles[id] ?? fallback,
  disclaimer: (fallback: string) => t.disclaimer || fallback,
});
