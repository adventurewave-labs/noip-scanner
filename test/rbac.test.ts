import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

// Golden guard (PRD R-4 / risk "RBAC scope creeps to secrets").
const docs = parseAllDocuments(readFileSync(new URL('../deploy/rbac.yaml', import.meta.url), 'utf8')).map((d) => d.toJS());
const role = docs.find((d) => d.kind === 'ClusterRole');

describe('deploy/rbac.yaml', () => {
  it('grants exactly the read access fetchSnapshot needs', () => {
    expect(role.rules).toEqual([
      { apiGroups: [''], resources: ['namespaces', 'pods', 'nodes', 'serviceaccounts'], verbs: ['get', 'list'] },
      { apiGroups: ['networking.k8s.io'], resources: ['networkpolicies'], verbs: ['get', 'list'] },
      { apiGroups: ['rbac.authorization.k8s.io'], resources: ['clusterrolebindings', 'rolebindings'], verbs: ['get', 'list'] },
    ]);
  });
  it('never grants secrets, wildcards or write verbs', () => {
    for (const r of role.rules) {
      expect(r.resources).not.toContain('secrets');
      expect(r.resources).not.toContain('*');
      expect(r.apiGroups).not.toContain('*');
      for (const v of r.verbs) expect(['get', 'list', 'watch']).toContain(v);
    }
  });
  it('is bound only to the noip ServiceAccount', () => {
    const b = docs.find((d) => d.kind === 'ClusterRoleBinding');
    expect(b.roleRef.name).toBe('noip-reader');
    expect(b.subjects).toEqual([{ kind: 'ServiceAccount', name: 'noip', namespace: 'noip-system' }]);
  });
});
