# NOIP — Kubernetes posture scanner

NOIP is a small, read-only Kubernetes posture scanner. It runs 15 deterministic checks covering pod security, NetworkPolicy coverage, RBAC, and the workload subset of CIS Kubernetes Benchmark Level 1. It produces a report in which every finding cites a concrete resource and field. An optional LLM layer can *explain* the findings, but it cannot add to or change them.

CI verifies it on every PR. A real `kind` cluster is seeded with known misconfigurations and scanned by NOIP under a ServiceAccount that has no `secrets` access. The result must match a golden file exactly, and the report is uploaded as a build artifact.

**What it is not:** network traffic analytics, anomaly detection, incident response, continuous monitoring, or a compliance attestation. SOC 2 and HIPAA identifiers in the report are *reference mappings*, and every report states this.

## Quick start

```bash
npm ci && npm run build

# Try it without a cluster (fixture data, labelled source: "demo")
node dist/cli.js scan --demo -o md

# Scan a real cluster with a read-only identity (recommended for client work)
kubectl apply -f deploy/rbac.yaml
scripts/sa-kubeconfig.sh noip.kubeconfig 1h
node dist/cli.js scan --kubeconfig noip.kubeconfig -o md --out report.md
node dist/cli.js scan --kubeconfig noip.kubeconfig --out report.json
```

This works with any kubeconfig, including kind, MicroK8s (`microk8s config > kc`) and managed clusters.

### `noip scan` options

| Flag | Meaning |
|---|---|
| `--kubeconfig <path>` / `--context <name>` | Which cluster to scan. Defaults to `$KUBECONFIG`, then `~/.kube/config`, then in-cluster. |
| `-o, --output json\|md\|sarif\|html` | Report format (default `json`). Each markdown `Evidence:` line is identical to the JSON `evidence` field. `sarif` is SARIF 2.1.0 (see [below](#sarif--code-scanning)). `html` is a single self-contained, print-ready file for client handoff: no scripts or external assets, light and dark themes, and every value escaped. |
| `--lang en\|es` | Language for the `md` and `html` reports; the default is `en`. JSON and SARIF always stay English and canonical. Spanish translates every label, check title, remediation, control title and disclaimer. Evidence and IDs are left as-is. |
| `--out <file>` | Write to a file instead of stdout. |
| `--explain` | Add an LLM explanation. Needs a key. If the provider fails, `explanation: null` and the scan still succeeds. |
| `--import-sarif <files...>` | Merge other scanners' SARIF 2.1.0 output (Trivy, kubescape, Checkov, KICS) into the report as `imported[]`, attributed to each tool. This never changes NOIP's score or control status. |
| `--netinspect <file>` | Merge a network-diagnostics JSON (see [below](#network-section)) into the report. |
| `--include-system` | Also scan `kube-system`, `kube-public` and `kube-node-lease`. These are skipped by default. |
| `--exclude-namespace <ns...>` | Skip more namespaces. |
| `--min-severity <severity>` | Only report findings at or above this severity. The summary and controls are computed from the kept findings, and the threshold is recorded in `provenance.minSeverity`. |
| `--fail-on <severity>` | Exit `2` if any finding is at or above this severity. Useful as a pipeline gate. |
| `--contexts <names...>` / `--all-contexts` + `--out-dir <dir>` | Scan several clusters in one run: one report per context in the chosen format, plus `fleet.json` and `fleet.md`. An unreachable cluster is recorded and the run continues, then exits `3`. `--fail-on` applies across all clusters. |
| `--manifests <paths...>` | Scan YAML files or directories offline instead of a cluster (see [below](#shift-left-manifest-scanning)). `-` reads stdin. |
| `--bundle <dir>` | Also write an audit evidence bundle (see [below](#audit-evidence-bundle)). |
| `--ignore-file <path>` / `--no-ignore` | Accepted-risk suppressions (see [below](#suppressions-accepted-risk)). `./.noip-ignore.yaml` is loaded automatically if it exists. |
| `--demo` | Scan `fixtures/demo-cluster.json` instead of a cluster (same as `NOIP_DEMO=1`). |

Exit codes: `0` ok · `1` error · `2` findings at the `--fail-on` threshold · `3` Kubernetes unreachable or forbidden · `4` `verify-bundle` failed.

## Checks

| ID | Severity | What | CIS control |
|---|---|---|---|
| NOIP-POD-001 | critical | Privileged container | 5.2.1 |
| NOIP-POD-002 | critical | `hostPID: true` | 5.2.2 |
| NOIP-POD-003 | high | `hostIPC: true` | 5.2.3 |
| NOIP-POD-004 | high | `hostNetwork: true` | 5.2.4 |
| NOIP-POD-005 | medium | `allowPrivilegeEscalation` not `false` | 5.2.5 |
| NOIP-POD-006 | high | May run as root. The pod-level securityContext is honoured. | 5.2.6 |
| NOIP-POD-007 | medium | Writable root filesystem | — |
| NOIP-POD-008 | low | Missing CPU or memory limit | — |
| NOIP-POD-009 | medium | Secret exposed as env var (`secretKeyRef` / `envFrom`) | 5.4.1 |
| NOIP-NS-001 | medium | Namespace does not enforce Pod Security Admission `baseline`/`restricted` | — |
| NOIP-NET-001 | high | Namespace has no NetworkPolicy | 5.3.2 |
| NOIP-NET-002 | medium | Egress rule with no destination, or to `0.0.0.0/0` / `::/0` without exceptions | — |
| NOIP-RBAC-001 | critical | `cluster-admin` granted by a ClusterRoleBinding *or RoleBinding* to `system:authenticated`, `system:unauthenticated`, `system:serviceaccounts[:ns]` or `User/system:anonymous` | 5.1.1 |
| NOIP-RBAC-002 | high | `cluster-admin` bound to a `default` ServiceAccount | 5.1.1, 5.1.5 |
| NOIP-RBAC-003 | medium | A RoleBinding grants to a `default` ServiceAccount | 5.1.5 |

Each finding also carries `references` to the relevant section of the **NSA/CISA Kubernetes Hardening Guide v1.2** and to the matching **NIST SP 800-190** section-4 risk. These, like the CIS/SOC 2/HIPAA mappings, are navigation aids, not an attestation.

Each check is a pure function over lists fetched once per scan (`src/checks/`). Container checks cover `containers`, `initContainers` and `ephemeralContainers`, so a privileged `kubectl debug` session is caught.

Each pod is attributed to the workload that owns it:

- 30 replicas of a Deployment produce one finding, not 30.
- Pods created by a CronJob are attributed to the CronJob, so finding IDs stay stable from one run to the next. The check set is now at its cap of 15 ([ADR-0004](docs/adr/0004-own-checks-capped.md)). If full CIS coverage is ever needed, the plan is to wrap kube-bench or kubescape rather than keep growing this set.

## Scale

- **Chunked lists.** Every cluster LIST call is fetched in pages of 500 using `limit`/`continue`, so a very large cluster never needs one giant response.
- **Expired lists.** If a continue token expires mid-list (HTTP 410), the list restarts once from the beginning so the result stays consistent.
- **Measured speed.** `npm run bench` on the cloud dev box:
  - 10k pods across 500 namespaces: scan in about 0.3 s, HTML plus SARIF in about 0.25 s, about 160 MB heap.
  - 50k pods: scan in about 1 s.
- **CI budget.** `test/scale.test.ts` runs a 10k-pod budget check on every PR.

## Kubernetes version support

Reports include `provenance.cluster.versionSupport`: whether the control-plane minor version is supported upstream, ending within 90 days, or past end of life, plus whether a newer patch exists. The data is a pinned copy of [kubernetes.io/releases](https://kubernetes.io/releases) taken on 2026-09-26, in `src/k8s/support.ts`; refresh it when upstream releases a new minor version. This is reported as a fact, not a check, so it doesn't change the score or use one of the 15 check slots. The markdown and HTML reports show a banner for it in English and Spanish. EKS, GKE, AKS and other managed platforms publish their own, often longer, support schedules, and the report says so.

## Pod Security readiness

Reports include a `podSecurity` section: for each namespace, the highest [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (`privileged`, `baseline` or `restricted`) it could enforce today without rejecting any of its current pods, plus the workloads that block the next level and why. It answers the question NOIP-NS-001 raises: which label is safe to set?

- **Evaluation.** `src/psa.ts` is a port of the upstream Pod Security Admission checks ([kubernetes/pod-security-admission](https://github.com/kubernetes/pod-security-admission), Apache-2.0). It is version-aware: it uses the cluster's minor version, capped at 1.37, and `latest` rules for manifest scans.
- **Conformance.** `test/psa.test.ts` runs upstream's own pass/fail fixtures (820 pods, policy versions 1.23 to 1.37, vendored under `test/fixtures/psa/` with their license) and requires the same verdict for every one.
- **Fixes.** The NS-001 fix labels a namespace with the level its pods already meet. A namespace whose pods don't meet baseline gets no automatic fix; fix the pods first, then run `noip fix` again.
- **Scoring.** Readiness is a planning aid. It doesn't change the score and doesn't use a check slot.

## Report

Reports validate against [`schemas/report.schema.json`](schemas/report.schema.json). Every report carries:

- **`source`:** `live` or `demo`. Demo data is only ever used when explicitly requested. If the cluster can't be reached, the scan fails with `K8sUnavailable`; it never falls back to demo data.
- **`provenance`:** the scanner version and git SHA, the cluster version from the `/version` API, the kubeconfig context, the node count, the scan timestamp, every check run, and the excluded namespaces.
- **`findings[]`:** each has a stable `id`, the resource, a one-line `evidence` string naming the offending field, the remediation, and the control IDs it maps to.
- **`controls[]`:** pass/fail per CIS control, with SOC 2 / HIPAA reference mappings and the disclaimer `reference mappings, not an attestation`.

The markdown and HTML reports open with an **executive summary**. It's fully deterministic, with no LLM involved. Findings are grouped by check and ranked by severity, then blast radius (cluster-wide, then namespace, then workload), then how many resources they touch. The summary also counts the quick wins that have a deterministic fix and the findings that need a design decision.

A sample is in [`docs/examples/demo-report.md`](docs/examples/demo-report.md).

## Audit evidence bundle

```bash
noip scan --kubeconfig noip.kubeconfig --bundle evidence/2026-09-acme
noip verify-bundle evidence/2026-09-acme          # or: (cd evidence/2026-09-acme && sha256sum -c SHA256SUMS)
```

The bundle directory holds:

- `report.json`, `report.md`, `report.html`, `report.sarif` and `report.oscal.json`
- `SHA256SUMS`
- `provenance.intoto.json`, an [in-toto v1 Statement](https://github.com/in-toto/attestation) whose subjects are the five reports and whose predicate is the scan's provenance

`verify-bundle` does five things: it recomputes every hash, rejects extra files, symlinks and path tricks, requires every listed file to be an in-toto subject, checks that the in-toto subjects match the sums, and cross-checks `report.json` against the statement. On failure it exits `4`.

**Signing (optional).** `--sign-key key.pem` also writes `provenance.intoto.dsse.json`: the statement's exact bytes in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope, signed with your own Ed25519 or ECDSA P-256 private key (PKCS#8 PEM, unencrypted). NOIP never generates or stores keys. `noip verify-bundle <dir> --key public.pem` then also requires a valid signature over exactly that statement; without `--key` it reports the signature as unverified.

```bash
openssl genpkey -algorithm ed25519 -out noip.key && openssl pkey -in noip.key -pubout -out noip.pub
noip scan --bundle evidence/2026-09-acme --sign-key noip.key
noip verify-bundle evidence/2026-09-acme --key noip.pub
# The envelope is standard DSSE, so Sigstore's cosign can check it too (checked with cosign v2.6.5, both key types):
cosign verify-blob-attestation --key noip.pub --insecure-ignore-tlog=true \
  --signature evidence/2026-09-acme/provenance.intoto.dsse.json \
  --type https://github.com/adventurewave-labs/noip-scanner/attestation/scan/v1 evidence/2026-09-acme/report.json
```

There is no transparency log or keyless (OIDC) signing; key custody is the operator's. NOIP refuses to write into a non-empty directory, so evidence from different scans never gets mixed.

## Posture drift: `noip diff`

```bash
noip scan --out 2026-09.json                     # this month
noip diff 2026-08.json 2026-09.json              # markdown drift report
noip diff 2026-08.json 2026-09.json --fail-on high -o json   # CI gate: exit 2 on NEW high+ findings
```

Findings are matched by their stable ID. The diff reports:

- new, resolved and unchanged findings
- changed evidence (same finding, different field or value)
- newly suppressed findings (accepted risk, so these don't count as resolved)
- control pass/fail changes, check-set changes and the score delta

It warns when the two reports come from different sources, targets or namespace scopes. It's designed for monthly retainer reviews, where the question is "what got worse since last time?"

`noip render report.json -o md|html|sarif [--lang es]` re-renders a saved report without rescanning.

## Posture history: `noip history`

```bash
noip history reports/                          # markdown: one table per target, with a trend line
noip history reports/ -o html --out trend.html # adds a score-over-time chart (no scripts)
noip history a.json b.json c.json -o json      # machine-readable series
```

It reads saved JSON reports (files, or directories searched for `*.json`) and groups them by target: source plus kubeconfig context. Each row shows the score, the change since the previous scan, findings by severity and the scanner version that produced it. Files that aren't NOIP reports, or whose `scannedAt` isn't a UTC ISO-8601 timestamp, are listed as skipped rather than failing the run. Report files are treated as untrusted input: counts are coerced to numbers and all text is escaped.

Scores are only comparable when the same checks ran with the same `--min-severity` over the same namespaces. When any of these changes between two scans, that row says "not comparable" and has no delta, so a narrower scan never shows up as an improvement. The HTML chart uses a fixed 0–100 axis, has a hover tooltip on each point, and keeps the data table next to it.

## Shift-left manifest scanning

`--manifests` runs the same 15 checks against manifests before they reach a cluster:

```bash
noip scan --manifests k8s/ --fail-on high                        # plain YAML files or directories
helm template my-chart | noip scan --manifests - -o sarif         # rendered Helm output
kustomize build overlays/prod | noip scan --manifests - -o md     # rendered Kustomize output
```

- **Workloads:** pod templates in Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs (including inside `List` objects) are checked and attributed to the workload.
- **Locations:** every finding records `file:line`, and SARIF results use that real location.
- **Report labelling:** reports carry `source: "manifests"`.
- **Missing namespaces:** objects that don't declare one are treated as `default`.
- **Limitation:** namespace-level checks only see `Namespace` objects that appear in the input.

In CI, the offline scan of `test/fixtures/misconfig/` has to produce exactly the same golden findings as the live kind scan.

## Admission policies: `noip policy`

```bash
noip policy > noip-policy.yaml                  # Warn + Audit: nothing is blocked
kubectl apply --dry-run=server -f noip-policy.yaml && kubectl apply -f noip-policy.yaml
noip policy --action deny --min-severity critical | kubectl apply -f -   # later, once warnings are clean
```

`noip scan` finds problems that are already running. `noip policy` prints the same rules as [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) objects with CEL expressions (`admissionregistration.k8s.io/v1`, Kubernetes 1.30 or later), so the API server can flag new problems at `kubectl apply` time. NOIP only prints YAML; it never applies anything.

- **Coverage:** POD-001 to POD-009 and NS-001, one policy and binding per check. The pod rules match Pods and the pod templates of Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs. NET and RBAC checks describe cluster state rather than a single object, so they stay in `noip scan`.
- **Safe default:** bindings use `Warn` + `Audit` with `failurePolicy: Ignore`. `--action deny` switches to `Deny` with `failurePolicy: Fail`.
- **Scope:** system namespaces are skipped unless `--include-system`; add more with `--exclude-namespace`. Filter with `--checks` or `--min-severity`.
- **Parity:** `test/policy.test.ts` evaluates every CEL rule against the demo cluster, the seeded fixtures and 400 random pods, and requires the same verdict as the check. The kind CI job applies the policies to a real API server and requires the NOIP warning in warn mode and a `denied request` with the NOIP message in deny mode. (Not yet run: GitHub Actions is unavailable for this repository at the moment.)
- **Pods on CREATE only.** Pod specs are almost immutable, and matching UPDATE would reject label or finalizer changes on pods admitted before the policy existed. Workload controllers are checked on CREATE and UPDATE.
- **`kubectl debug`:** container-level policies also match the `pods/ephemeralcontainers` subresource and check only the new debug containers. POD-008 doesn't apply to ephemeral containers, because the API rejects resource limits on them.
- **Type checking:** one expression reads either a Pod or a workload's pod template, so the API server's per-kind type check may list warnings for fields that exist only on the other kinds. Evaluation is unaffected; the kind job prints them.

## Fixes: `noip fix`

When a finding has a fix that needs no judgement call, it carries `fix: {description, patch}`. The patch is an RFC 6902 JSON Patch against the finding's own object, and it uses the correct pod-spec path for each workload kind: Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob and so on.

- **Fixes applied:** privileged → false; `allowPrivilegeEscalation: false` (also dropping `privileged`, since the API rejects that combination); `runAsNonRoot: true`; `readOnlyRootFilesystem: true`; removing `hostPID`, `hostIPC` and `hostNetwork`; and a PSA `enforce: restricted` label on the namespace.
- **Left for you:** resource limits, secret mounts, NetworkPolicies and RBAC. These are listed as needing a human.

```bash
noip fix k8s/ --out-dir k8s-fixed      # patched copy of the whole tree (untouched files mirrored)
noip fix k8s/ --in-place               # or edit in place; run it again and nothing changes
```

`noip fix` keeps comments, document order, unrelated documents, `List` wrappers and the file's own flow-collection style, and it doesn't re-wrap lines. It never fixes a suppressed finding. After running it, a rescan shows only the findings that still need a human.

## Suppressions (accepted risk)

A suppression hides a finding you've decided to accept. Each entry names the finding by exact ID, or by check plus a resource glob, and must include a `reason`, an `owner` and an `expires` date. See [`docs/examples/noip-ignore.example.yaml`](docs/examples/noip-ignore.example.yaml).

- **Nothing disappears silently.** Suppressed findings move to `report.suppressed[]` together with their justification, get a markdown section of their own, and appear in SARIF as `suppressions: [{status: "accepted"}]`, which code-scanning tools display as dismissed.
- **Expiry is enforced.** A suppression stops applying the day after its `expires` date, and its findings come back with a warning. Suppressions that match nothing are flagged as stale.
- **What counts.** Scores, control status and `--fail-on` use active findings only; `summary.suppressed` reports how many were suppressed.
- **API.** Suppressions come only from an operator-set `NOIP_IGNORE_FILE`, never from the request.

## SARIF / code scanning

`-o sarif` emits SARIF 2.1.0, validated in tests against the official OASIS schema (`schemas/vendor/`). It includes:

- One rule per check, with remediation and control references.
- One result per finding, with GitHub `security-severity` scores: critical 9.5, high 8.0, medium 5.5, low 3.0.
- Stable `partialFingerprints`, so a re-scan updates existing alerts instead of duplicating them.

Findings from live clusters use the pseudo-path `k8s/<Kind>/<namespace>/<name>`; manifest findings use their real file and line. The output can be loaded into GitHub code scanning (`github/codeql-action/upload-sarif`), which needs GitHub Code Security on private repos, as well as the VS Code SARIF Viewer, DefectDojo and Azure DevOps.

## In CI and before commit

**GitHub Action.** `action.yml` is a composite action that builds NOIP from the pinned revision, scans, writes JSON and SARIF, adds the Markdown report to the job summary and fails at `fail-on`:

```yaml
- uses: adventurewave-labs/noip-scanner@<commit-sha>
  id: noip
  with:
    manifests: k8s/            # or kubeconfig: path/to/read-only.kubeconfig
    fail-on: high              # empty = never fail
- uses: github/codeql-action/upload-sarif@<commit-sha>
  if: always()
  with:
    sarif_file: ${{ steps.noip.outputs.sarif-file }}
```

Outputs: `score`, `findings`, `sarif-file`, `report-file`. The cluster or files are scanned once; SARIF and the job summary are rendered from that JSON with `noip render`, so all outputs describe the same snapshot. `actions/setup-node` runs only if the runner has no Node 22+, so the job's Node version is otherwise left alone. `manifests` may be space- or newline-separated. Inputs reach the script through environment variables only, never by template expansion inside `run`. While this repository is private, other repositories can only use the action if its Actions access settings allow it.

**pre-commit.** `.pre-commit-hooks.yaml` defines a `noip` hook for staged `*.yaml`/`*.yml` files. It needs Node 22+ and npm on `PATH`; the first run builds the scanner inside pre-commit's cache (about 15 seconds), and later runs only scan.

```yaml
repos:
  - repo: https://github.com/adventurewave-labs/noip-scanner
    rev: <commit-sha>
    hooks:
      - id: noip
        args: [--fail-on, critical]   # default: high
```

`noip scan <paths...>` is the same as `noip scan --manifests <paths...>`, which is what the hook uses. Put paths before options that take several values (`--import-sarif`, `--contexts`), or after `--`. Well-formed non-Kubernetes YAML is ignored; YAML that doesn't parse fails the hook. Helm chart `templates/` are excluded, since they are Go templates; scan `helm template … | noip scan --manifests -` instead. The CI `action-smoke` job runs the action on the seeded fixtures (clean passes, seeded fails) and runs the hook script both ways.

## OSCAL assessment results

`-o oscal` (on `scan`, `render` and fleet runs) emits [NIST OSCAL](https://pages.nist.gov/OSCAL/) 1.2.3 Assessment Results JSON, for GRC tools that ingest OSCAL. Evidence bundles include it as `report.oscal.json`.

- One observation per finding (evidence, severity, remediation, the affected resource as an inventory item).
- One OSCAL finding per mapped CIS control, marked `satisfied` or `not-satisfied`, linked to its observations.
- UUIDs are deterministic (v5), so the same report always produces the same document.
- Tests validate the output against the official OSCAL schema, vendored in `schemas/vendor/`.

Limits: the control IDs are CIS Kubernetes Benchmark IDs as NOIP maps them (the same caveat as the report's mapping disclaimer), not controls from an imported OSCAL catalog. There is no assessment plan or SSP; `import-ap` points to a back-matter entry that says so. It's machine-readable evidence, not an authorization package.

## LLM explanation (optional)

| Variable | Default |
|---|---|
| `NOIP_LLM_PROVIDER` | `anthropic` (or `openai-compatible`) |
| `NOIP_LLM_MODEL` | Pinned in `src/llm/provider.ts` for Anthropic. Required for `openai-compatible`. |
| `ANTHROPIC_API_KEY` or `NOIP_LLM_API_KEY` | — |
| `NOIP_LLM_BASE_URL` | For `openai-compatible`, e.g. `https://openrouter.ai/api/v1`, or GLM's OpenAI-compatible endpoint |

The model only ever sees a projection of the deterministic report: finding IDs, severities, titles, evidence strings and failed control IDs. That projection passes through `redact()` first, which drops `env`, `annotations`, `data`, `stringData` and `value` keys and scrubs token-shaped strings. Raw Kubernetes objects are never sent, and NOIP has no `secrets` access in the first place.

The output is validated with zod. Any priority that cites a finding ID not in the report is dropped. If validation fails, the provider errors, or no key is set, you get the deterministic report with `explanation: null` from the CLI, or HTTP 501 from `/api/report/explain`. The scan itself is unaffected in every case. Tests use a fake provider. A real-provider run is available as a manual `workflow_dispatch` job (`llm_live: true`), which uses the `ANTHROPIC_API_KEY` secret.

## MCP server (for AI agents)

`noip mcp` serves the scanner over MCP (stdio), so Claude Code, Turbo Flow or any other MCP client can run posture audits as tool calls:

```bash
claude mcp add noip -- node /path/to/noip-scanner/dist/cli.js mcp
```

| Tool | What it returns |
|---|---|
| `scan` | The full report for the current kubeconfig, a given `kubeconfig`/`context`, offline `manifests`, or `demo`. Accepts an optional `minSeverity` filter. |
| `list_checks` | The check catalog: ids, severities, CIS controls and remediation. |
| `explain_finding` | One finding by id, with its remediation, control status, SOC 2/HIPAA reference mappings, and suppression status. |

All three tools are read-only and marked with `readOnlyHint`. Two safety limits apply. Tool calls **cannot choose the kubeconfig**: an operator sets it with `noip mcp --kubeconfig`, because a kubeconfig can run `exec` credential plugins. `manifests` paths must also resolve inside the server's working directory. They use the caller's kubeconfig and RBAC, and apply `.noip-ignore.yaml` unless you pass `--no-ignore`. No LLM runs inside NOIP here; the calling agent does the reasoning over deterministic findings. An unreachable cluster comes back as a tool error, not a crash. CI starts the real stdio server and calls it with the official MCP client (`scripts/mcp-smoke.mjs`).

## HTTP API (optional)

```bash
NOIP_API_TOKEN=$(openssl rand -hex 24) node dist/api/server.js     # or docker build -t noip . && docker run …
```

| Route | Auth | Notes |
|---|---|---|
| `GET /openapi.json` | open | OpenAPI 3.1 description. The Report schema in it is the same JSON Schema that validates CLI output. |
| `GET /health` | open | `ok` or `degraded`. Reports `degraded` when Kubernetes is unreachable, never `healthy`. |
| `GET /api/scan[?includeSystem=1]` | bearer | Full report. Returns 503 `K8sUnavailable` when there is no cluster. |
| `GET /api/discovery/cluster` | bearer | Version, node, namespace, pod and NetworkPolicy counts |
| `POST /api/report/explain` | bearer | Report plus explanation. Returns 501 if no LLM key is set. |
| `GET /` | open | In demo mode only, a public HTML page with a **DEMO MODE** banner |

The server refuses to start without `NOIP_API_TOKEN` (or `NOIP_API_TOKEN_FILE`), which must be at least 16 characters. `deploy/deployment.yaml` mounts the token as a file, so NOIP does not trip its own NOIP-POD-009 check. There is no user database, no MFA, and no Mongo or Redis ([ADR-0002](docs/adr/0002-bearer-token-auth.md)).

**Railway preview:** `railway.json` builds the Dockerfile. Set `NOIP_DEMO=1` and `NOIP_API_TOKEN` on the service. No cluster credential ever goes to Railway.

## Network section

`--netinspect <file>` accepts JSON matching [`schemas/netinspect-input.schema.json`](schemas/netinspect-input.schema.json): `{tool, version, cni, checks: [{name, status: pass|warn|fail|info, detail?, resource?}]}`. NOIP stores it verbatim under `network`, with a sha256 of the input, and performs no diagnosis of its own. `k8s-netinspect` does not emit JSON yet. This schema is the contract for when it does.

## How it's verified

`.github/workflows/ci.yml` is the only workflow. It has no schedules and never deploys or pushes images.

1. **verify:** typecheck, lint, doc-lint, unit tests with a coverage gate, a coverage ratchet (thresholds in `coverage-thresholds.json` may only go up), build, and a schema check on the demo report.
2. **kind-scan:** creates a kind cluster, applies `deploy/rbac.yaml` and `test/fixtures/misconfig/`, mints a read-only kubeconfig, asserts that it *cannot* read secrets, runs the CLI, validates the schema, and compares against `test/golden/kind-findings.json`. The comparison requires exactly the seeded findings, zero findings in `noip-test-clean`, and that the seeded secret value is absent from the report. `report.json` and `report.md` are uploaded as artifacts.
3. **docker-smoke:** the image refuses to start without a token; `/health` returns 200 with status `degraded`; `/api/*` returns 401 without a token and 503 without a cluster; explain returns 501; demo mode returns 200 with `source:"demo"`.
4. **ci:** a single aggregate job. Make this the required check on `main`.

`test/properties.test.ts` uses fast-check to check invariants on random clusters:

- reports are always schema-valid, internally consistent and deterministic;
- the result doesn't depend on the order pods are returned in;
- a report diffed against itself is empty;
- suppressions split findings into active and suppressed with nothing lost or duplicated;
- secret values never survive redaction.

It also fuzzes the manifest parser. The fuzzer has already found and fixed one real crash: an unresolved YAML alias.

`test/golden.test.ts` runs the same fixture YAMLs through the checks offline, so a golden mismatch fails before kind even starts.

## Supply chain

The `supply-chain` CI job checks every PR in four ways:

- `npm audit --omit=dev --audit-level=high` blocks known high/critical vulnerabilities in runtime dependencies.
- `npm audit signatures` verifies registry signatures and provenance attestations.
- A CycloneDX 1.5 SBOM of the runtime tree is generated and uploaded as the `sbom` artifact (`scripts/supply-chain.mjs`).
- A license allowlist (MIT, Apache-2.0, ISC, BSD and similar permissive licenses) fails the build on anything else.

In addition, GitHub Actions are pinned to commit SHAs, and the Docker runtime stage installs with `--ignore-scripts` and runs as a non-root user.

## Running CI without GitHub

`npm run ci:local` (`scripts/ci-local.sh`) runs every CI gate that doesn't need Docker, in the same order as CI and starting from a clean `dist/`. The gates are typecheck, lint, doc-lint, unit tests with the coverage gate, the ratchet check against `NOIP_BASE_REF`, build, demo schema validation, the manifest golden comparison, the MCP stdio smoke test, `npm audit`, and SBOM plus license checks. `NOIP_CI_DOCKER=1` also builds the image if Docker is available.

## Where it sits in the estate

| Sibling | NOIP's stance |
|---|---|
| `rustops` (anomaly detection, incidents) | NOIP does none of this. |
| `aops-sre-pipeline` (alert narration to Slack) | No alerting, no Slack. |
| `agentic-devops-extravaganza` (k8sgpt on kind) | Closest overlap. NOIP differs in three ways: it covers **posture** rather than runtime faults; it uses **deterministic control IDs with golden tests**; and its LLM use is **redacted and schema-validated**, and the LLM can't create findings. |
| `k8s-netinspect` (CNI diagnostics) | NOIP only ingests its output (`--netinspect`). |

## Development

```bash
npm run typecheck && npm run lint && npm run doc-lint && npm run coverage && npm run build
```

See [CLAUDE.md](CLAUDE.md) for repo conventions, [docs/PRD.md](docs/PRD.md) for the spec, [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for requirement traceability, and [docs/adr/](docs/adr/) for decisions.

## License

MIT
