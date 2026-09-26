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
| `--out <file>` | Write to a file instead of stdout. |
| `--explain` | Add an LLM explanation. Needs a key. If the provider fails, `explanation: null` and the scan still succeeds. |
| `--netinspect <file>` | Merge a network-diagnostics JSON (see [below](#network-section)) into the report. |
| `--include-system` | Also scan `kube-system`, `kube-public` and `kube-node-lease`. These are skipped by default. |
| `--exclude-namespace <ns...>` | Skip more namespaces. |
| `--min-severity <severity>` | Only report findings at or above this severity. The summary and controls are computed from the kept findings, and the threshold is recorded in `provenance.minSeverity`. |
| `--fail-on <severity>` | Exit `2` if any finding is at or above this severity. Useful as a pipeline gate. |
| `--manifests <paths...>` | Scan YAML files or directories offline instead of a cluster (see [below](#shift-left-manifest-scanning)). `-` reads stdin. |
| `--ignore-file <path>` / `--no-ignore` | Accepted-risk suppressions (see [below](#suppressions-accepted-risk)). `./.noip-ignore.yaml` is loaded automatically if it exists. |
| `--demo` | Scan `fixtures/demo-cluster.json` instead of a cluster (same as `NOIP_DEMO=1`). |

Exit codes: `0` ok · `1` error · `2` findings at the `--fail-on` threshold · `3` Kubernetes unreachable or forbidden.

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

Each check is a pure function over lists fetched once per scan (`src/checks/`). Container checks cover `containers`, `initContainers` and `ephemeralContainers`, so a privileged `kubectl debug` session is caught.

Each pod is attributed to the workload that owns it:

- 30 replicas of a Deployment produce one finding, not 30.
- Pods created by a CronJob are attributed to the CronJob, so finding IDs stay stable from one run to the next. The check set is now at its cap of 15 ([ADR-0004](docs/adr/0004-own-checks-capped.md)). If full CIS coverage is ever needed, the plan is to wrap kube-bench or kubescape rather than keep growing this set.

## Report

Reports validate against [`schemas/report.schema.json`](schemas/report.schema.json). Every report carries:

- **`source`:** `live` or `demo`. Demo data is only ever used when explicitly requested. If the cluster can't be reached, the scan fails with `K8sUnavailable`; it never falls back to demo data.
- **`provenance`:** the scanner version and git SHA, the cluster version from the `/version` API, the kubeconfig context, the node count, the scan timestamp, every check run, and the excluded namespaces.
- **`findings[]`:** each has a stable `id`, the resource, a one-line `evidence` string naming the offending field, the remediation, and the control IDs it maps to.
- **`controls[]`:** pass/fail per CIS control, with SOC 2 / HIPAA reference mappings and the disclaimer `reference mappings, not an attestation`.

A sample is in [`docs/examples/demo-report.md`](docs/examples/demo-report.md).

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

`test/golden.test.ts` runs the same fixture YAMLs through the checks offline, so a golden mismatch fails before kind even starts.

## Supply chain

The `supply-chain` CI job checks every PR in four ways:

- `npm audit --omit=dev --audit-level=high` blocks known high/critical vulnerabilities in runtime dependencies.
- `npm audit signatures` verifies registry signatures and provenance attestations.
- A CycloneDX 1.5 SBOM of the runtime tree is generated and uploaded as the `sbom` artifact (`scripts/supply-chain.mjs`).
- A license allowlist (MIT, Apache-2.0, ISC, BSD and similar permissive licenses) fails the build on anything else.

In addition, GitHub Actions are pinned to commit SHAs, and the Docker runtime stage installs with `--ignore-scripts` and runs as a non-root user.

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
