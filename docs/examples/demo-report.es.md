# Reporte de postura NOIP

> **DATOS DE DEMOSTRACIÓN.** Este reporte se generó con el fixture incluido `fixtures/demo-cluster.json`, no con un clúster real.

| | |
|---|---|
| Origen | `demo` |
| Fecha del análisis | 2026-09-26T21:19:09.241Z |
| Clúster | demo-shop — Kubernetes v1.31.4 (linux/amd64), 3 nodo(s) |
| Escáner | noip 0.1.0 @ `62f9c2bef9ff` |
| Revisiones ejecutadas | 15 (NOIP-POD-001, NOIP-POD-002, NOIP-POD-003, NOIP-POD-004, NOIP-POD-005, NOIP-POD-006, NOIP-POD-007, NOIP-POD-008, NOIP-POD-009, NOIP-NS-001, NOIP-NET-001, NOIP-NET-002, NOIP-RBAC-001, NOIP-RBAC-002, NOIP-RBAC-003) |
| Namespaces excluidos | kube-node-lease, kube-public, kube-system |

## Resumen

Puntaje **12/100** · 25 hallazgo(s) · 2 crítico, 9 alto, 12 medio, 2 bajo · 14/15 revisiones con fallas · 10/10 controles con fallas

> ⚠️ Kubernetes 1.31 ya no tiene soporte upstream (fin de vida: 2025-11-11) y no recibe correcciones de seguridad (calendario upstream de kubernetes.io al 2026-09-26; las plataformas administradas como EKS, GKE y AKS publican el suyo). Existe un parche más reciente: 1.31.14.

## Resumen ejecutivo

Puntaje 12/100. 25 hallazgo(s) (2 críticos, 9 altos) en 14 de 15 revisiones; 12 tienen una corrección determinista.

Corregir primero (orden determinista: severidad, luego alcance, luego número de recursos):

1. **NOIP-POD-001: Contenedor privilegiado**: crítico, alcance: carga de trabajo, 1 recurso(s), 1 con corrección automática (p. ej. `Pod/ci/debug-shell`)
2. **NOIP-POD-002: El pod comparte el espacio de PID del host**: crítico, alcance: carga de trabajo, 1 recurso(s), 1 con corrección automática (p. ej. `DaemonSet/monitoring/node-exporter`)
3. **NOIP-RBAC-002: cluster-admin otorgado a una ServiceAccount default**: alto, alcance: clúster, 1 recurso(s) (p. ej. `ClusterRoleBinding/ci-deployer-admin`)
4. **NOIP-NET-001: Namespace sin NetworkPolicy**: alto, alcance: namespace, 3 recurso(s) (p. ej. `Namespace/ci`, `Namespace/default`, `Namespace/payments`)
5. **NOIP-POD-006: El contenedor podría ejecutarse como root**: alto, alcance: carga de trabajo, 3 recurso(s), 3 con corrección automática (p. ej. `Deployment/payments/api`, `Pod/ci/debug-shell`)

Mejoras rápidas con corrección determinista: **12** · requieren una decisión de diseño: **13**

## Hallazgos

### [CRÍTICO] NOIP-POD-001 — Contenedor privilegiado

- Recurso: `Pod/ci/debug-shell/shell`
- Evidencia: spec.containers[shell].securityContext.privileged=true
- Remediación: Quitar securityContext.privileged: true; otorgar solo las capacidades de Linux específicas que se necesiten.
- Controles: CIS-5.2.1
- Referencias: NSA/CISA Kubernetes Pod security · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-001:Pod/ci/debug-shell/shell`

### [CRÍTICO] NOIP-POD-002 — El pod comparte el espacio de PID del host

- Recurso: `DaemonSet/monitoring/node-exporter`
- Evidencia: spec.hostPID=true
- Remediación: Quitar hostPID: true de la especificación del pod.
- Controles: CIS-5.2.2
- Referencias: NSA/CISA Kubernetes Pod security · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-002:DaemonSet/monitoring/node-exporter`

### [ALTO] NOIP-NET-001 — Namespace sin NetworkPolicy

- Recurso: `Namespace/ci`
- Evidencia: 0 NetworkPolicy objects in namespace ci
- Remediación: Agregar una NetworkPolicy de denegación por defecto (entrada y salida) y reglas explícitas de permiso.
- Controles: CIS-5.3.2
- Referencias: NSA/CISA Network policies · NIST SP 800-190 4.3.3 Poorly separated inter-container network traffic
- ID del hallazgo: `NOIP-NET-001:Namespace/ci`

### [ALTO] NOIP-NET-001 — Namespace sin NetworkPolicy

- Recurso: `Namespace/default`
- Evidencia: 0 NetworkPolicy objects in namespace default
- Remediación: Agregar una NetworkPolicy de denegación por defecto (entrada y salida) y reglas explícitas de permiso.
- Controles: CIS-5.3.2
- Referencias: NSA/CISA Network policies · NIST SP 800-190 4.3.3 Poorly separated inter-container network traffic
- ID del hallazgo: `NOIP-NET-001:Namespace/default`

### [ALTO] NOIP-NET-001 — Namespace sin NetworkPolicy

- Recurso: `Namespace/payments`
- Evidencia: 0 NetworkPolicy objects in namespace payments
- Remediación: Agregar una NetworkPolicy de denegación por defecto (entrada y salida) y reglas explícitas de permiso.
- Controles: CIS-5.3.2
- Referencias: NSA/CISA Network policies · NIST SP 800-190 4.3.3 Poorly separated inter-container network traffic
- ID del hallazgo: `NOIP-NET-001:Namespace/payments`

### [ALTO] NOIP-POD-003 — El pod comparte el espacio IPC del host

- Recurso: `Pod/ci/debug-shell`
- Evidencia: spec.hostIPC=true
- Remediación: Quitar hostIPC: true de la especificación del pod.
- Controles: CIS-5.2.3
- Referencias: NSA/CISA Kubernetes Pod security · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-003:Pod/ci/debug-shell`

### [ALTO] NOIP-POD-004 — El pod usa la red del host

- Recurso: `DaemonSet/monitoring/node-exporter`
- Evidencia: spec.hostNetwork=true
- Remediación: Quitar hostNetwork: true, salvo que la carga sea un agente de nodo que realmente lo necesite.
- Controles: CIS-5.2.4
- Referencias: NSA/CISA Kubernetes Pod security; Network separation and hardening · NIST SP 800-190 4.4.3 Insecure container runtime configurations; 4.4.2 Unbounded network access from containers
- ID del hallazgo: `NOIP-POD-004:DaemonSet/monitoring/node-exporter`

### [ALTO] NOIP-POD-006 — El contenedor podría ejecutarse como root

- Recurso: `Deployment/payments/api/api`
- Evidencia: spec.containers[api]: runAsNonRoot and runAsUser unset at pod and container level
- Remediación: Establecer runAsNonRoot: true (en el securityContext del pod o del contenedor) y un runAsUser distinto de cero.
- Controles: CIS-5.2.6
- Referencias: NSA/CISA Non-root containers and "rootless" container engines · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-006:Deployment/payments/api/api`

### [ALTO] NOIP-POD-006 — El contenedor podría ejecutarse como root

- Recurso: `Deployment/payments/api/migrate`
- Evidencia: spec.initContainers[migrate]: runAsNonRoot and runAsUser unset at pod and container level
- Remediación: Establecer runAsNonRoot: true (en el securityContext del pod o del contenedor) y un runAsUser distinto de cero.
- Controles: CIS-5.2.6
- Referencias: NSA/CISA Non-root containers and "rootless" container engines · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-006:Deployment/payments/api/migrate`

### [ALTO] NOIP-POD-006 — El contenedor podría ejecutarse como root

- Recurso: `Pod/ci/debug-shell/shell`
- Evidencia: spec.containers[shell]: runAsNonRoot and runAsUser unset at pod and container level
- Remediación: Establecer runAsNonRoot: true (en el securityContext del pod o del contenedor) y un runAsUser distinto de cero.
- Controles: CIS-5.2.6
- Referencias: NSA/CISA Non-root containers and "rootless" container engines · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-006:Pod/ci/debug-shell/shell`

### [ALTO] NOIP-RBAC-002 — cluster-admin otorgado a una ServiceAccount default

- Recurso: `ClusterRoleBinding/ci-deployer-admin`
- Evidencia: roleRef=ClusterRole/cluster-admin subject=ServiceAccount/ci/default
- Remediación: Crear una ServiceAccount dedicada con un rol de mínimo privilegio; nunca asignar cluster-admin a `default`.
- Controles: CIS-5.1.1, CIS-5.1.5
- Referencias: NSA/CISA Authentication and authorization · NIST SP 800-190 4.3.1 Unbounded administrative access
- ID del hallazgo: `NOIP-RBAC-002:ClusterRoleBinding/ci-deployer-admin`

### [MEDIO] NOIP-NET-002 — NetworkPolicy permite salida a cualquier destino

- Recurso: `NetworkPolicy/shop/allow-egress`
- Evidencia: spec.egress[0] has no 'to' selector (all destinations allowed)
- Remediación: Dar a cada regla de salida un `to` explícito (namespaceSelector/podSelector/ipBlock) y puertos.
- Controles: —
- Referencias: NSA/CISA Network policies · NIST SP 800-190 4.4.2 Unbounded network access from containers
- ID del hallazgo: `NOIP-NET-002:NetworkPolicy/shop/allow-egress`

### [MEDIO] NOIP-NS-001 — Pod Security Admission no aplica baseline ni restricted

- Recurso: `Namespace/ci`
- Evidencia: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediación: Etiquetar el namespace con pod-security.kubernetes.io/enforce=restricted (o baseline si restricted aún no es viable), después de una prueba con pod-security.kubernetes.io/warn.
- Controles: —
- Referencias: NSA/CISA Pod security enforcement · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-NS-001:Namespace/ci`

### [MEDIO] NOIP-NS-001 — Pod Security Admission no aplica baseline ni restricted

- Recurso: `Namespace/default`
- Evidencia: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediación: Etiquetar el namespace con pod-security.kubernetes.io/enforce=restricted (o baseline si restricted aún no es viable), después de una prueba con pod-security.kubernetes.io/warn.
- Controles: —
- Referencias: NSA/CISA Pod security enforcement · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-NS-001:Namespace/default`

### [MEDIO] NOIP-NS-001 — Pod Security Admission no aplica baseline ni restricted

- Recurso: `Namespace/monitoring`
- Evidencia: metadata.labels["pod-security.kubernetes.io/enforce"]=privileged
- Remediación: Etiquetar el namespace con pod-security.kubernetes.io/enforce=restricted (o baseline si restricted aún no es viable), después de una prueba con pod-security.kubernetes.io/warn.
- Controles: —
- Referencias: NSA/CISA Pod security enforcement · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-NS-001:Namespace/monitoring`

### [MEDIO] NOIP-NS-001 — Pod Security Admission no aplica baseline ni restricted

- Recurso: `Namespace/payments`
- Evidencia: metadata.labels["pod-security.kubernetes.io/enforce"] unset (no admission-time pod security)
- Remediación: Etiquetar el namespace con pod-security.kubernetes.io/enforce=restricted (o baseline si restricted aún no es viable), después de una prueba con pod-security.kubernetes.io/warn.
- Controles: —
- Referencias: NSA/CISA Pod security enforcement · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-NS-001:Namespace/payments`

### [MEDIO] NOIP-POD-005 — Escalamiento de privilegios no deshabilitado

- Recurso: `DaemonSet/monitoring/node-exporter/node-exporter`
- Evidencia: spec.containers[node-exporter].securityContext.allowPrivilegeEscalation=unset
- Remediación: Establecer securityContext.allowPrivilegeEscalation: false en cada contenedor.
- Controles: CIS-5.2.5
- Referencias: NSA/CISA Kubernetes Pod security · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-005:DaemonSet/monitoring/node-exporter/node-exporter`

### [MEDIO] NOIP-POD-005 — Escalamiento de privilegios no deshabilitado

- Recurso: `Pod/ci/debug-shell/shell`
- Evidencia: spec.containers[shell].securityContext.allowPrivilegeEscalation=unset
- Remediación: Establecer securityContext.allowPrivilegeEscalation: false en cada contenedor.
- Controles: CIS-5.2.5
- Referencias: NSA/CISA Kubernetes Pod security · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-005:Pod/ci/debug-shell/shell`

### [MEDIO] NOIP-POD-007 — Sistema de archivos raíz con escritura

- Recurso: `Deployment/shop/frontend/frontend`
- Evidencia: spec.containers[frontend].securityContext.readOnlyRootFilesystem=false
- Remediación: Establecer securityContext.readOnlyRootFilesystem: true y montar volúmenes emptyDir para las rutas que requieran escritura.
- Controles: —
- Referencias: NSA/CISA Immutable container file systems · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-007:Deployment/shop/frontend/frontend`

### [MEDIO] NOIP-POD-007 — Sistema de archivos raíz con escritura

- Recurso: `Pod/ci/debug-shell/shell`
- Evidencia: spec.containers[shell].securityContext.readOnlyRootFilesystem=unset
- Remediación: Establecer securityContext.readOnlyRootFilesystem: true y montar volúmenes emptyDir para las rutas que requieran escritura.
- Controles: —
- Referencias: NSA/CISA Immutable container file systems · NIST SP 800-190 4.4.3 Insecure container runtime configurations
- ID del hallazgo: `NOIP-POD-007:Pod/ci/debug-shell/shell`

### [MEDIO] NOIP-POD-009 — Secreto expuesto como variable de entorno

- Recurso: `Deployment/payments/api/api`
- Evidencia: spec.containers[api]: env[STRIPE_KEY] &lt;- secret stripe/api-key
- Remediación: Montar el secreto como volumen de solo lectura en lugar de env.valueFrom.secretKeyRef / envFrom.secretRef.
- Controles: CIS-5.4.1
- Referencias: NSA/CISA Secrets · NIST SP 800-190 —
- ID del hallazgo: `NOIP-POD-009:Deployment/payments/api/api`

### [MEDIO] NOIP-POD-009 — Secreto expuesto como variable de entorno

- Recurso: `Deployment/payments/api/migrate`
- Evidencia: spec.initContainers[migrate]: envFrom &lt;- secret payments-db
- Remediación: Montar el secreto como volumen de solo lectura en lugar de env.valueFrom.secretKeyRef / envFrom.secretRef.
- Controles: CIS-5.4.1
- Referencias: NSA/CISA Secrets · NIST SP 800-190 —
- ID del hallazgo: `NOIP-POD-009:Deployment/payments/api/migrate`

### [MEDIO] NOIP-RBAC-003 — Rol asignado a una ServiceAccount default

- Recurso: `RoleBinding/payments/payments-reader`
- Evidencia: roleRef=Role/config-reader subject=ServiceAccount/payments/default
- Remediación: Asignar el rol a una ServiceAccount con nombre y dejar `default` sin permisos.
- Controles: CIS-5.1.5
- Referencias: NSA/CISA Authentication and authorization · NIST SP 800-190 4.3.2 Unauthorized access
- ID del hallazgo: `NOIP-RBAC-003:RoleBinding/payments/payments-reader`

### [BAJO] NOIP-POD-008 — Falta el límite de CPU o memoria

- Recurso: `Deployment/shop/frontend/frontend`
- Evidencia: spec.containers[frontend].resources.limits missing cpu, memory
- Remediación: Definir resources.limits.cpu y resources.limits.memory.
- Controles: —
- Referencias: NSA/CISA Resource policies · NIST SP 800-190 —
- ID del hallazgo: `NOIP-POD-008:Deployment/shop/frontend/frontend`

### [BAJO] NOIP-POD-008 — Falta el límite de CPU o memoria

- Recurso: `Pod/ci/debug-shell/shell`
- Evidencia: spec.containers[shell].resources.limits missing cpu, memory
- Remediación: Definir resources.limits.cpu y resources.limits.memory.
- Controles: —
- Referencias: NSA/CISA Resource policies · NIST SP 800-190 —
- ID del hallazgo: `NOIP-POD-008:Pod/ci/debug-shell/shell`

## Controles

| Control | Título | Estado | Hallazgos | SOC 2 (ref.) | HIPAA (ref.) |
|---|---|---|---|---|---|
| CIS-5.1.1 | El rol cluster-admin se usa solo donde es necesario | ❌ no cumple | 1 | CC6.1, CC6.3 | 164.312(a)(1) |
| CIS-5.1.5 | Las ServiceAccount default no se usan activamente | ❌ no cumple | 2 | CC6.1, CC6.3 | 164.312(a)(1) |
| CIS-5.2.1 | Minimizar la admisión de contenedores privilegiados | ❌ no cumple | 1 | CC6.1, CC6.6 | 164.312(a)(1), 164.312(c)(1) |
| CIS-5.2.2 | Minimizar contenedores que comparten el espacio de PID del host | ❌ no cumple | 1 | CC6.1 | 164.312(a)(1) |
| CIS-5.2.3 | Minimizar contenedores que comparten el espacio IPC del host | ❌ no cumple | 1 | CC6.1 | 164.312(a)(1) |
| CIS-5.2.4 | Minimizar contenedores que comparten la red del host | ❌ no cumple | 1 | CC6.1, CC6.6 | 164.312(a)(1) |
| CIS-5.2.5 | Minimizar contenedores con allowPrivilegeEscalation | ❌ no cumple | 2 | CC6.1, CC6.6 | 164.312(c)(1) |
| CIS-5.2.6 | Minimizar la admisión de contenedores root | ❌ no cumple | 3 | CC6.1 | 164.312(a)(1) |
| CIS-5.3.2 | Todos los namespaces tienen NetworkPolicies definidas | ❌ no cumple | 3 | CC6.6, CC6.7 | 164.312(a)(1), 164.312(e)(1) |
| CIS-5.4.1 | Preferir secretos como archivos en lugar de variables de entorno | ❌ no cumple | 2 | CC6.1, CC6.7 | 164.312(a)(2)(iv), 164.312(e)(2)(ii) |

_Los identificadores de SOC 2, HIPAA, NSA/CISA y NIST SP 800-190 son mapeos de referencia, no una certificación. NOIP revisa un subconjunto de cargas de trabajo del CIS Kubernetes Benchmark nivel 1 y no evalúa controles del plano de control, de nodos ni de procesos._

## Preparación para Pod Security

El estándar de Pod Security más alto que cada namespace podría aplicar hoy sin rechazar ningún pod actual (versión de política 1.31, evaluada con una adaptación de las comprobaciones oficiales de Pod Security Admission). Es una ayuda de planificación; no afecta la puntuación.

| Namespace | Aplicado ahora | Podría aplicar hoy | Pods | Bloquea el siguiente nivel |
|---|---|---|---|---|
| ci | sin definir | **privileged** | 1 | **Pod/ci/debug-shell**: hostIPC=true; privileged containers (shell) |
| default | sin definir | **restricted** | 0 | — |
| monitoring | privileged | **privileged** | 3 | **DaemonSet/monitoring/node-exporter**: hostNetwork, hostPID=true |
| payments | sin definir | **baseline** | 1 | **Deployment/payments/api**: pod or containers must set runAsNonRoot=true (migrate, api); pod or containers must set seccompProfile RuntimeDefault or Localhost (migrate, api) |
| shop | restricted | **restricted** | 3 | — |
