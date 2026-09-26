# NOIP posture report

> **DEMO DATA.** This report was generated from the bundled fixture `fixtures/demo-cluster.json`, not a live cluster.

| | |
|---|---|
| Source | `demo` |
| Scanned at | 2026-09-26T14:37:58.552Z |
| Cluster | demo-shop — Kubernetes v1.31.4 (linux/amd64), 3 node(s) |
| Scanner | noip 0.1.0 @ `b98eeb0da767` |
| Checks run | 15 (NOIP-POD-001, NOIP-POD-002, NOIP-POD-003, NOIP-POD-004, NOIP-POD-005, NOIP-POD-006, NOIP-POD-007, NOIP-POD-008, NOIP-POD-009, NOIP-NS-001, NOIP-NET-001, NOIP-NET-002, NOIP-RBAC-001, NOIP-RBAC-002, NOIP-RBAC-003) |
| Excluded namespaces | kube-node-lease, kube-public, kube-system |

## Summary

Score **12/100** · 25 finding(s) · 2 critical, 9 high, 12 medium, 2 low · 14/15 checks failed · 10/10 controls failed

## Findings

### [CRITICAL] NOIP-POD-001 — Privileged container

- Resource: `Pod/ci/debug-shell/shell`
- Evidence: spec.containers[shell].securityContext.privileged=true
- Remediation: Remove securityContext.privileged: true; grant only the specific Linux capabilities required.
- Controls: CIS-5.2.1
- Finding ID: `NOIP-POD-001:Pod/ci/debug-shell/shell`

### [CRITICAL] NOIP-POD-002 — Pod shares the host PID namespace

- Resource: `DaemonSet/monitoring/node-exporter`
- Evidence: spec.hostPID=true
- Remediation: Remove hostPID: true from the pod spec.
- Controls: CIS-5.2.2
- Finding ID: `NOIP-POD-002:DaemonSet/monitoring/node-exporter`

### [HIGH] NOIP-NET-001 — Namespace has no NetworkPolicy

- Resource: `Namespace/ci`
- Evidence: 0 NetworkPolicy objects in namespace ci
- Remediation: Add a default-deny NetworkPolicy (ingress and egress) plus explicit allow rules.
- Controls: CIS-5.3.2
- Finding ID: `NOIP-NET-001:Namespace/ci`

### [HIGH] NOIP-NET-001 — Namespace has no NetworkPolicy

- Resource: `Namespace/default`
- Evidence: 0 NetworkPolicy objects in namespace default
- Remediation: Add a default-deny NetworkPolicy (ingress and egress) plus explicit allow rules.
- Controls: CIS-5.3.2
- Finding ID: `NOIP-NET-001:Namespace/default`

### [HIGH] NOIP-NET-001 — Namespace has no NetworkPolicy

- Resource: `Namespace/payments`
- Evidence: 0 NetworkPolicy objects in namespace payments
- Remediation: Add a default-deny NetworkPolicy (ingress and egress) plus explicit allow rules.
- Controls: CIS-5.3.2
- Finding ID: `NOIP-NET-001:Namespace/payments`

### [HIGH] NOIP-POD-003 — Pod shares the host IPC namespace

- Resource: `Pod/ci/debug-shell`
- Evidence: spec.hostIPC=true
- Remediation: Remove hostIPC: true from the pod spec.
- Controls: CIS-5.2.3
- Finding ID: `NOIP-POD-003:Pod/ci/debug-shell`

### [HIGH] NOIP-POD-004 — Pod uses the host network

- Resource: `DaemonSet/monitoring/node-exporter`
- Evidence: spec.hostNetwork=true
- Remediation: Remove hostNetwork: true unless the workload is a node-level agent that genuinely needs it.
- Controls: CIS-5.2.4
- Finding ID: `NOIP-POD-004:DaemonSet/monitoring/node-exporter`

### [HIGH] NOIP-POD-006 — Container may run as root

- Resource: `Deployment/payments/api/api`
- Evidence: spec.containers[api]: runAsNonRoot and runAsUser unset at pod and container level
- Remediation: Set runAsNonRoot: true (pod or container securityContext) and a non-zero runAsUser.
- Controls: CIS-5.2.6
- Finding ID: `NOIP-POD-006:Deployment/payments/api/api`

### [HIGH] NOIP-POD-006 — Container may run as root

- Resource: `Deployment/payments/api/migrate`
- Evidence: spec.initContainers[migrate]: runAsNonRoot and runAsUser unset at pod and container level
- Remediation: Set runAsNonRoot: true (pod or container securityContext) and a non-zero runAsUser.
- Controls: CIS-5.2.6
- Finding ID: `NOIP-POD-006:Deployment/payments/api/migrate`

### [HIGH] NOIP-POD-006 — Container may run as root

- Resource: `Pod/ci/debug-shell/shell`
- Evidence: spec.containers[shell]: runAsNonRoot and runAsUser unset at pod and container level
- Remediation: Set runAsNonRoot: true (pod or container securityContext) and a non-zero runAsUser.
- Controls: CIS-5.2.6
- Finding ID: `NOIP-POD-006:Pod/ci/debug-shell/shell`

### [HIGH] NOIP-RBAC-002 — cluster-admin granted to a default ServiceAccount

- Resource: `ClusterRoleBinding/ci-deployer-admin`
- Evidence: roleRef=ClusterRole/cluster-admin subject=ServiceAccount/ci/default
- Remediation: Create a dedicated ServiceAccount with a least-privilege role; never bind cluster-admin to `default`.
- Controls: CIS-5.1.1, CIS-5.1.5
- Finding ID: `NOIP-RBAC-002:ClusterRoleBinding/ci-deployer-admin`

### [MEDIUM] NOIP-NET-002 — NetworkPolicy allows egress to any destination

- Resource: `NetworkPolicy/shop/allow-egress`
- Evidence: spec.egress[0] has no 'to' selector (all destinations allowed)
- Remediation: Give every egress rule an explicit `to` (namespaceSelector/podSelector/ipBlock) and ports.
- Controls: —
- Finding ID: `NOIP-NET-002:NetworkPolicy/shop/allow-egress`

### [MEDIUM] NOIP-NS-001 — Pod Security Admission not enforcing baseline or restricted

- Resource: `Namespace/ci`
- Evidence: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediation: Label the namespace pod-security.kubernetes.io/enforce=restricted (or baseline where restricted is not yet feasible), after a dry run with pod-security.kubernetes.io/warn.
- Controls: —
- Finding ID: `NOIP-NS-001:Namespace/ci`

### [MEDIUM] NOIP-NS-001 — Pod Security Admission not enforcing baseline or restricted

- Resource: `Namespace/default`
- Evidence: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediation: Label the namespace pod-security.kubernetes.io/enforce=restricted (or baseline where restricted is not yet feasible), after a dry run with pod-security.kubernetes.io/warn.
- Controls: —
- Finding ID: `NOIP-NS-001:Namespace/default`

### [MEDIUM] NOIP-NS-001 — Pod Security Admission not enforcing baseline or restricted

- Resource: `Namespace/monitoring`
- Evidence: metadata.labels["pod-security.kubernetes.io/enforce"]=privileged
- Remediation: Label the namespace pod-security.kubernetes.io/enforce=restricted (or baseline where restricted is not yet feasible), after a dry run with pod-security.kubernetes.io/warn.
- Controls: —
- Finding ID: `NOIP-NS-001:Namespace/monitoring`

### [MEDIUM] NOIP-NS-001 — Pod Security Admission not enforcing baseline or restricted

- Resource: `Namespace/payments`
- Evidence: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediation: Label the namespace pod-security.kubernetes.io/enforce=restricted (or baseline where restricted is not yet feasible), after a dry run with pod-security.kubernetes.io/warn.
- Controls: —
- Finding ID: `NOIP-NS-001:Namespace/payments`

### [MEDIUM] NOIP-POD-005 — Privilege escalation not disabled

- Resource: `DaemonSet/monitoring/node-exporter/node-exporter`
- Evidence: spec.containers[node-exporter].securityContext.allowPrivilegeEscalation=unset
- Remediation: Set securityContext.allowPrivilegeEscalation: false on every container.
- Controls: CIS-5.2.5
- Finding ID: `NOIP-POD-005:DaemonSet/monitoring/node-exporter/node-exporter`

### [MEDIUM] NOIP-POD-005 — Privilege escalation not disabled

- Resource: `Pod/ci/debug-shell/shell`
- Evidence: spec.containers[shell].securityContext.allowPrivilegeEscalation=unset
- Remediation: Set securityContext.allowPrivilegeEscalation: false on every container.
- Controls: CIS-5.2.5
- Finding ID: `NOIP-POD-005:Pod/ci/debug-shell/shell`

### [MEDIUM] NOIP-POD-007 — Writable root filesystem

- Resource: `Deployment/shop/frontend/frontend`
- Evidence: spec.containers[frontend].securityContext.readOnlyRootFilesystem=false
- Remediation: Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for writable paths.
- Controls: —
- Finding ID: `NOIP-POD-007:Deployment/shop/frontend/frontend`

### [MEDIUM] NOIP-POD-007 — Writable root filesystem

- Resource: `Pod/ci/debug-shell/shell`
- Evidence: spec.containers[shell].securityContext.readOnlyRootFilesystem=unset
- Remediation: Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for writable paths.
- Controls: —
- Finding ID: `NOIP-POD-007:Pod/ci/debug-shell/shell`

### [MEDIUM] NOIP-POD-009 — Secret exposed as environment variable

- Resource: `Deployment/payments/api/api`
- Evidence: spec.containers[api]: env[STRIPE_KEY] <- secret stripe/api-key
- Remediation: Mount the secret as a read-only volume instead of env.valueFrom.secretKeyRef / envFrom.secretRef.
- Controls: CIS-5.4.1
- Finding ID: `NOIP-POD-009:Deployment/payments/api/api`

### [MEDIUM] NOIP-POD-009 — Secret exposed as environment variable

- Resource: `Deployment/payments/api/migrate`
- Evidence: spec.initContainers[migrate]: envFrom <- secret payments-db
- Remediation: Mount the secret as a read-only volume instead of env.valueFrom.secretKeyRef / envFrom.secretRef.
- Controls: CIS-5.4.1
- Finding ID: `NOIP-POD-009:Deployment/payments/api/migrate`

### [MEDIUM] NOIP-RBAC-003 — Role bound to a default ServiceAccount

- Resource: `RoleBinding/payments/payments-reader`
- Evidence: roleRef=Role/config-reader subject=ServiceAccount/payments/default
- Remediation: Bind the role to a named ServiceAccount and leave `default` without permissions.
- Controls: CIS-5.1.5
- Finding ID: `NOIP-RBAC-003:RoleBinding/payments/payments-reader`

### [LOW] NOIP-POD-008 — Missing CPU or memory limit

- Resource: `Deployment/shop/frontend/frontend`
- Evidence: spec.containers[frontend].resources.limits missing cpu, memory
- Remediation: Define resources.limits.cpu and resources.limits.memory.
- Controls: —
- Finding ID: `NOIP-POD-008:Deployment/shop/frontend/frontend`

### [LOW] NOIP-POD-008 — Missing CPU or memory limit

- Resource: `Pod/ci/debug-shell/shell`
- Evidence: spec.containers[shell].resources.limits missing cpu, memory
- Remediation: Define resources.limits.cpu and resources.limits.memory.
- Controls: —
- Finding ID: `NOIP-POD-008:Pod/ci/debug-shell/shell`

## Controls

| Control | Title | Status | Findings | SOC 2 (ref) | HIPAA (ref) |
|---|---|---|---|---|---|
| CIS-5.1.1 | cluster-admin role is only used where required | ❌ fail | 1 | CC6.1, CC6.3 | 164.312(a)(1) |
| CIS-5.1.5 | Default service accounts are not actively used | ❌ fail | 2 | CC6.1, CC6.3 | 164.312(a)(1) |
| CIS-5.2.1 | Minimize the admission of privileged containers | ❌ fail | 1 | CC6.1, CC6.6 | 164.312(a)(1), 164.312(c)(1) |
| CIS-5.2.2 | Minimize containers sharing the host PID namespace | ❌ fail | 1 | CC6.1 | 164.312(a)(1) |
| CIS-5.2.3 | Minimize containers sharing the host IPC namespace | ❌ fail | 1 | CC6.1 | 164.312(a)(1) |
| CIS-5.2.4 | Minimize containers sharing the host network namespace | ❌ fail | 1 | CC6.1, CC6.6 | 164.312(a)(1) |
| CIS-5.2.5 | Minimize containers with allowPrivilegeEscalation | ❌ fail | 2 | CC6.1, CC6.6 | 164.312(c)(1) |
| CIS-5.2.6 | Minimize the admission of root containers | ❌ fail | 3 | CC6.1 | 164.312(a)(1) |
| CIS-5.3.2 | All namespaces have NetworkPolicies defined | ❌ fail | 3 | CC6.6, CC6.7 | 164.312(a)(1), 164.312(e)(1) |
| CIS-5.4.1 | Prefer secrets as files over secrets as environment variables | ❌ fail | 2 | CC6.1, CC6.7 | 164.312(a)(2)(iv), 164.312(e)(2)(ii) |

_SOC 2 and HIPAA identifiers are reference mappings, not an attestation. NOIP checks a workload subset of CIS Kubernetes Benchmark Level 1 and does not assess control-plane, node or process controls._
