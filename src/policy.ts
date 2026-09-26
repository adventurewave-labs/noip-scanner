import { stringify } from 'yaml';
import { ALL_CHECKS, SYSTEM_NAMESPACES } from './checks/index.js';
import { SEVERITIES, type Severity } from './types.js';

/**
 * Policy-as-code export: the admission-time twin of NOIP's pod and namespace checks, as
 * ValidatingAdmissionPolicy (admissionregistration.k8s.io/v1, GA in Kubernetes 1.30) with CEL rules.
 *
 * NOIP itself stays read-only: this only prints YAML. Applying it is the operator's decision, and the
 * default binding is Warn + Audit so nothing is denied until someone chooses `--action deny`.
 * Each CEL rule mirrors its check's logic; `test/policy.test.ts` evaluates every rule against the same
 * pods the checks see and requires identical verdicts.
 */

/** The pod spec of a Pod or of any workload template (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob). */
const POD_SPEC =
  "object.kind == 'Pod' ? object.spec : (object.kind == 'CronJob' ? object.spec.jobTemplate.spec.template.spec : object.spec.template.spec)";
/** Regular and init containers. Ephemeral containers are added through a subresource these policies don't match. */
const CONTAINERS = "variables.spec.containers + (has(variables.spec.initContainers) ? variables.spec.initContainers : [])";

const sc = (field: string) => `has(c.securityContext) && has(c.securityContext.${field})`;
const podSc = (field: string) => `has(variables.spec.securityContext) && has(variables.spec.securityContext.${field})`;

export const CEL_RULES: Record<string, string> = {
  'NOIP-POD-001': `variables.containers.all(c, !(${sc('privileged')}) || c.securityContext.privileged == false)`,
  'NOIP-POD-002': '!has(variables.spec.hostPID) || variables.spec.hostPID == false',
  'NOIP-POD-003': '!has(variables.spec.hostIPC) || variables.spec.hostIPC == false',
  'NOIP-POD-004': '!has(variables.spec.hostNetwork) || variables.spec.hostNetwork == false',
  'NOIP-POD-005': `variables.containers.all(c, ${sc('allowPrivilegeEscalation')} && c.securityContext.allowPrivilegeEscalation == false)`,
  // Effective values: the container setting wins over the pod setting (same precedence as the check).
  'NOIP-POD-006':
    'variables.containers.all(c, ' +
    `(${sc('runAsUser')} ? c.securityContext.runAsUser != 0 : !(${podSc('runAsUser')} && variables.spec.securityContext.runAsUser == 0)) && (` +
    `(${sc('runAsNonRoot')} ? c.securityContext.runAsNonRoot == true : (${podSc('runAsNonRoot')} && variables.spec.securityContext.runAsNonRoot == true)) || ` +
    `(${sc('runAsUser')} ? c.securityContext.runAsUser > 0 : (${podSc('runAsUser')} && variables.spec.securityContext.runAsUser > 0))))`,
  'NOIP-POD-007': `variables.containers.all(c, ${sc('readOnlyRootFilesystem')} && c.securityContext.readOnlyRootFilesystem == true)`,
  'NOIP-POD-008':
    "variables.containers.all(c, has(c.resources) && has(c.resources.limits) && 'cpu' in c.resources.limits && 'memory' in c.resources.limits)",
  'NOIP-POD-009':
    'variables.containers.all(c, (!has(c.env) || c.env.all(e, !has(e.valueFrom) || !has(e.valueFrom.secretKeyRef))) && (!has(c.envFrom) || c.envFrom.all(e, !has(e.secretRef))))',
  'NOIP-NS-001':
    "has(object.metadata.labels) && 'pod-security.kubernetes.io/enforce' in object.metadata.labels && object.metadata.labels['pod-security.kubernetes.io/enforce'] in ['baseline', 'restricted']",
};

/** Checks that describe cluster state rather than one admitted object (for example, a namespace with no NetworkPolicy). */
export const NOT_ADMISSION_SHAPED = ALL_CHECKS.map((c) => c.id).filter((id) => !(id in CEL_RULES));

export type PolicyAction = 'warn' | 'audit' | 'deny';

export interface PolicyOptions {
  checks?: string[];
  minSeverity?: Severity;
  action?: PolicyAction;
  includeSystemNamespaces?: boolean;
  excludeNamespaces?: string[];
}

const WORKLOADS = [
  { apiGroups: [''], apiVersions: ['v1'], resources: ['pods'] },
  { apiGroups: ['apps'], apiVersions: ['v1'], resources: ['deployments', 'statefulsets', 'daemonsets', 'replicasets'] },
  { apiGroups: ['batch'], apiVersions: ['v1'], resources: ['jobs', 'cronjobs'] },
];

export function policyDocuments(opts: PolicyOptions = {}): object[] {
  const action = opts.action ?? 'warn';
  const limit = SEVERITIES.indexOf(opts.minSeverity ?? 'low');
  const wanted = opts.checks?.length ? new Set(opts.checks) : undefined;
  if (wanted) {
    const unknown = [...wanted].filter((id) => !ALL_CHECKS.some((c) => c.id === id));
    if (unknown.length) throw new Error(`unknown check id(s): ${unknown.join(', ')}`);
    const notAdmission = [...wanted].filter((id) => !(id in CEL_RULES));
    if (notAdmission.length) throw new Error(`not expressible as an admission policy: ${notAdmission.join(', ')}`);
  }
  const bad = (opts.excludeNamespaces ?? []).filter((n) => !/^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/.test(n));
  if (bad.length) throw new Error(`invalid namespace name(s): ${bad.join(', ')}`);
  const excluded = [...new Set([...(opts.includeSystemNamespaces ? [] : SYSTEM_NAMESPACES), ...(opts.excludeNamespaces ?? [])])].sort();
  const namespaceSelector = excluded.length ? { matchExpressions: [{ key: 'kubernetes.io/metadata.name', operator: 'NotIn', values: excluded }] } : {};
  const validationActions = action === 'deny' ? ['Deny'] : action === 'audit' ? ['Audit'] : ['Warn', 'Audit'];

  const docs: object[] = [];
  for (const check of ALL_CHECKS) {
    const rule = CEL_RULES[check.id];
    if (!rule || (wanted && !wanted.has(check.id)) || SEVERITIES.indexOf(check.severity) > limit) continue;
    const name = check.id.toLowerCase();
    const isNs = check.id === 'NOIP-NS-001';
    const labels = { 'app.kubernetes.io/managed-by': 'noip', 'noip-check': name, 'noip-severity': check.severity };
    docs.push({
      apiVersion: 'admissionregistration.k8s.io/v1',
      kind: 'ValidatingAdmissionPolicy',
      metadata: { name, labels },
      spec: {
        // Deny mode fails closed on evaluation errors; warn/audit never blocks a request.
        failurePolicy: action === 'deny' ? 'Fail' : 'Ignore',
        matchConstraints: isNs
          ? { resourceRules: [{ apiGroups: [''], apiVersions: ['v1'], operations: ['CREATE', 'UPDATE'], resources: ['namespaces'] }] }
          : { resourceRules: WORKLOADS.map((w) => ({ ...w, operations: ['CREATE', 'UPDATE'] })) },
        ...(isNs
          ? {
              matchConditions: excluded.length ? [{ name: 'not-excluded', expression: `!(object.metadata.name in ${JSON.stringify(excluded).replace(/"/g, "'")})` }] : undefined,
            }
          : { variables: [{ name: 'spec', expression: POD_SPEC }, { name: 'containers', expression: CONTAINERS }] }),
        validations: [{ expression: rule, message: `${check.id} ${check.title}. ${check.remediation}`, reason: 'Forbidden' }],
      },
    });
    docs.push({
      apiVersion: 'admissionregistration.k8s.io/v1',
      kind: 'ValidatingAdmissionPolicyBinding',
      metadata: { name, labels },
      spec: { policyName: name, validationActions, ...(isNs ? {} : { matchResources: { namespaceSelector } }) },
    });
  }
  return docs.map(stripUndefined);
}

const stripUndefined = (o: object): object => JSON.parse(JSON.stringify(o)) as object;

export function renderPolicies(opts: PolicyOptions = {}): string {
  const docs = policyDocuments(opts);
  const action = opts.action ?? 'warn';
  const header = [
    '# Generated by `noip policy`: ValidatingAdmissionPolicy (admissionregistration.k8s.io/v1, Kubernetes >= 1.30).',
    `# Binding action: ${action === 'deny' ? 'Deny (non-compliant requests are rejected)' : action === 'audit' ? 'Audit (annotations in the audit log only)' : 'Warn + Audit (nothing is blocked)'}.`,
    '# Try it first: kubectl apply --dry-run=server -f <this file>, then apply, then watch for warnings before switching to --action deny.',
    `# Not expressible at admission (cluster-state checks, still covered by \`noip scan\`): ${NOT_ADMISSION_SHAPED.join(', ')}.`,
  ];
  return header.join('\n') + '\n' + docs.map((d) => '---\n' + stringify(d, { lineWidth: 0 })).join('');
}
