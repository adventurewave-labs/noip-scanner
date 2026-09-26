> **Implementation note (2026-09-25).** This PRD is implemented in `adventurewave-labs/noip-scanner`, a clean-slate repository that ports only the verified check logic from `adventurewave-labs/NOIP`. Sections 2 and 2.5 describe that predecessor repository. See `docs/adr/0001-clean-slate-repo.md` and the traceability table in `docs/REQUIREMENTS.md`.

# NOIP — Revival PRD

**Pitch:** A small, honest, read-only Kubernetes posture scanner: deterministic checks (pod security, NetworkPolicy coverage, RBAC, a handful of CIS L1 controls), verified against a real `kind` cluster in CI, with an optional LLM layer that *explains* findings. The goal is SRE proof you can show a client, not an "enterprise platform".

| | |
|---|---|
| Repo | `adventurewave-labs/NOIP` (private) |
| Stack | TypeScript 5.9, Node 20 (Docker/CI), Express 5, `@kubernetes/client-node` ^0.22, `@anthropic-ai/sdk` ^0.52. Mongo/Redis are used by auth only. Standalone Python scripts sit alongside. |
| Created | 2025-09-23 |
| Feature work stopped | **2026-06-17** (last service code: AI/Security/Compliance services, commits `fb16570`…`80a42cb`). Build/CI fixes continued to 2026-06-24. Every commit from 2026-08-30 to 09-03 is CI-YAML and README hygiene. |
| Doc status | Draft v1 — 2026-09-25 |

---

## 1. Why revive it now

- **It supports the CTM "Day 2" story.** Creando Tu Matrix is moving toward ROI audits, reliability retainers, an Agentic Observatory spec and Policy-as-Code. A scanner that turns cluster state into evidence-backed findings, mapped to controls, is a concrete demo of the "posture audit" part of that offer. The checks are deterministic and the LLM only narrates, which matches the reliability-first positioning.
- **The expensive parts already exist and are real.** `src/services/security.service.ts` and `src/services/compliance.service.ts` contain genuine Kubernetes-API checks, written 2026-06-17. They have never run against a live cluster, so the revival is mostly wiring, verification and deletion, not new building.
- **The README is already honest.** Commit `1258a79` (2026-09-03) rewrote it against the code, so the reputational risk of the old oversold release notes is contained. The code still carries the oversell, though (`/health` returns `phase: 'Phase 3 - Production Ready (100%)'`). The revival should bring the code in line with the README.
- **It fits the estate if its scope is narrow.** NOIPPLAN.md originally described NOIP as glue over Marcus's own tools (`k8s-netinspect`, secret-scan, driftguard, file-hasher, cargocrypt). A narrow posture scanner that can later consume `k8s-netinspect` output fits the estate without duplicating siblings (§7.4).

## 2. Current state (verified)

All paths below were read at `main@1258a79`.

### 2.1 Works (verified by reading code/tests)
- **K8s security checks** (`src/services/security.service.ts`). Real API calls: privileged containers, runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation, missing limits, hostNetwork/PID/IPC; namespaces without a NetworkPolicy and unrestricted egress; cluster-admin bound to broad groups or the default SA. There is a weighted score and a top-10 recommendations list.
- **Compliance** (`src/services/compliance.service.ts`). Six real checks (CIS 5.1.1, 5.2.1, 5.2.2, 5.2.5, 5.3.2, 5.4.1), mapped to SOC2 and HIPAA identifiers.
- **Discovery** (`src/services/discovery.service.ts`). Real `listNode/Namespace/Pod/Service/Deployment` calls.
- **AI** (`src/services/ai.service.ts`). Makes real Anthropic `messages.create` calls. Issue #4's "mock adapter" framing is stale.
- **Auth service layer.** Argon2id, JWT, TOTP (per the README table and `docs/architecture/IMPLEMENTATION_STATUS.md`).
- **Python scripts.** `scripts/file-hasher.py` and `scripts/security-testing-framework.py` are functional, per the README verification pass.

### 2.2 Stubbed, mocked or simulated
- **Silent fixture fallback everywhere.** Discovery returns a hardcoded 3-node cluster (`BASELINE_CLUSTER`, `BASELINE_NODES`) whenever the API errors *or returns empty*. The security service returns `BASELINE` findings in the same cases. Both `healthCheck()`s return `healthy` even when Kubernetes is unreachable. As a result, a live cluster with zero findings looks the same as no cluster at all.
- **Unit tests treat the fixture as the contract.** `tests/unit/services/discovery.service.test.ts` asserts `name === 'noip-cluster'` and `version === 'v1.28.2'`. These tests will fail against any real cluster.
- **`PerformanceService` is fully simulated** (`src/services/performance.service.ts`). `simulateRequest()` sleeps a random time and never makes an HTTP call. `getSystemMetrics()` returns `Math.random()` values. The "load test" measures nothing.
- **`DashboardService.getWidgetData()` returns random mock data** of a random widget type (`src/services/dashboard.service.ts`). Dashboards live in an in-memory Map.
- **MFA SMS/email only log the code.** There is no provider (README table; issue #5).
- **`scripts/generate_dashboard.py` displays hardcoded placeholder metrics.**

### 2.3 Claimed but absent
- **The GitHub repo description is wrong.** It says "real-time network infrastructure monitoring, anomaly detection, traffic analytics, and automated incident response". None of these exist in `src/`. The only "network" code is NetworkPolicy coverage, plus random `network.bytesIn` values in the simulated performance metrics.
- **`CLAUDE.md` contradicts the code:**
  - It claims 7 domains under `/api/v1/*`, but routes mount at `/api/*` and `IMPLEMENTATION_STATUS.md` confirms there is no `/v1` (ADR-0020 🔴).
  - It says the AI service is mocked; it is real.
  - It points to repo `marcuspat/NOIP` and to `docs/ADR/`, `docs/DDD/` and `USE_CASE_GUIDE.md`, none of which match.
- **Issues cite files that don't exist.** #3 cites `__mocks__/kubernetes*` (only `__mocks__/uuid.js` exists). #6 cites `jest.config.ts` and `src/services/AIService.ts` (the real files are `jest.config.cjs` and `ai.service.ts`). #5 cites `POST /api/v1/auth/mfa/send`.
- **The deployment pipeline targets placeholders.** `ci-cd.yml` deploys to `staging.noip.company.com` and `noip.company.com` using `KUBE_CONFIG_*` secrets and a Slack webhook that are not configured. The performance job runs `scripts/performance-test.js`, which is absent from `scripts/`.
- **ADR-0011** (AgentDB/ReasoningBank ports) and **ADR-0013** (compliance aggregates) are planned only (`IMPLEMENTATION_STATUS.md`).

### 2.4 Known bugs and suspected blockers
Items marked (S) come from reading, not running. Phase 0 must confirm them.

1. **All `/api/*` routes are unauthenticated.** `src/app.ts` mounts no auth middleware, and `auth.routes.ts` is never mounted. `/api/ai/*` forwards arbitrary request JSON to Anthropic on the owner's key, with no redaction.
2. **The AI model ID is `claude-3-5-sonnet-20241022`.** This model has been retired by Anthropic (S: expect 404s). The ID is hardcoded in 5 places, and `JSON.parse` has no fence or schema tolerance.
3. **The compiled server is unlikely to boot (S).** Four separate causes:
   - `"type": "module"`, `moduleResolution: node10` and extensionless relative imports (`'./config'`) will not resolve under Node ESM.
   - `rootDir: "./"` makes `tsc` emit `dist/src/app.js`, but `start` and the Docker `CMD` run `dist/app.js`.
   - `express`, `cors`, `helmet`, `winston`, `dotenv` and `jsonwebtoken` are in **devDependencies**, and the Docker runtime stage installs with `--omit=dev`.
   - `app.use('*', …)` is an invalid Express 5 / path-to-regexp v8 pattern.
4. **`tests/integration/api.test.ts` disagrees with the routes.** It POSTs to `/api/security/scan`, but the route is `GET` and reads `req.body`. It expects AI responses with `insights/recommendations/confidence`, a shape the service never returns.
5. **`tests/kubernetes/k8s.test.ts` only lints manifests,** by string-matching and `kubectl apply --dry-run`. It also asserts on `k8s/security/pod-security-policy.yaml`, a PodSecurityPolicy, which Kubernetes removed in 1.25.
6. **The scan response carries no provenance.** The `DiscoveryService` scan interval starts on `initialize()` if `config.services.discovery.enabled` is set, and nothing tells the caller whether data came from a live cluster or fixtures.
7. **Scheduled workflows burn private-repo Actions minutes.** `monitoring.yml` runs every 5 minutes (`*/5 * * * *`) and hourly, `infrastructure-scan.yml` every 6 hours, and `security.yml` and `security-audit.yml` daily. Branch `claude/disable-repo-actions-xkuclt` (2026-06-21) strips these triggers but was **never merged**.
8. **`ci-cd.yml` cannot gate merges.** It pushes images to GHCR even on PRs (`push: true`), the coverage, integration and e2e steps are `continue-on-error`, and the file includes a production-deploy job that fires on push to `main`.

### 2.5 Open issues and PRs: what to do
| Item | Verdict | Action |
|---|---|---|
| #7 CI pipeline | **Right priority. Do first.** | Rewrite as R-1: one `ci.yml`, all other workflows deleted. |
| #3 Real K8s discovery | **Right, but re-scope.** The client is already wired; the real gaps are the silent fallback and the missing live test. | Re-scope to R-3/R-4: remove the silent fallback and test against `kind` in CI. |
| #4 Real LLM provider | **Stale.** Anthropic is already called. | Re-scope to R-6: provider seam, current model ID, redaction, schema validation. |
| #5 SMS/email MFA | **Wrong priority.** Building Twilio/SendGrid delivery for a single-operator demo adds cost, secrets and attack surface for no demo value. | Close as won't-do (R-2 / §10 D2). |
| #6 80% coverage | **Wrong framing.** 80% of a codebase that is half simulated is vanity. | Re-scope to R-9: ratchet gate on the retained core only. |
| PR #9 (closed, unmerged) | Only an `echo "CI passing"` job. | Leave closed and delete branch `marcuspat-patch-1`. |
| PR #1 / #8 (merged), PR #2 (closed) | Historical. | Delete merged/stale branches `claude/*` and `fix/production-ready` after Phase 1. |

## 3. Goals
- **G1.** `noip scan` against a real cluster produces a findings report. Every finding cites a concrete resource, and the report states its data source (`live` or `demo`).
- **G2.** Every PR runs typecheck, lint, unit tests and a `kind`-cluster scan with seeded misconfigurations, and the checks must pass before merge.
- **G3.** An optional LLM explanation layer sits behind a provider-agnostic seam. It redacts inputs, validates outputs against a schema, and can be turned off.
- **G4.** Repo, README, CLAUDE.md, the GitHub description and the code all agree.

## 4. Non-goals
- Network traffic analytics, anomaly detection, alert correlation or incident response. rustops and aops-sre-pipeline own these.
- Multi-tenant SaaS, user management, SMS/email MFA or RBAC UI.
- Load testing or synthetic performance metrics.
- CNI/datapath diagnostics. `k8s-netinspect` owns this; NOIP may *ingest* its JSON later (P2).
- Continuous in-cluster monitoring loops, or scheduled GitHub Actions scans.
- "SOC2/HIPAA compliance". The framework IDs are *reference mappings*, and output must say so.

## 5. Users and core use cases
- **Marcus / CTM consultant.** Runs a one-off read-only scan of a client or lab cluster (MicroK8s, Rackspace managed K8s) and hands over the report as posture-audit evidence.
- **Prospect / reviewer.** Opens the repo or a Railway preview, sees a clearly labeled demo report, and can reproduce a live result from CI artifacts.
- **Claude Code session.** Runs phases autonomously in a cloud dev environment; a human merges.

## 6. Requirements

**R-1 (P0): Single enforced CI workflow.**
Replace all six workflows with `.github/workflows/ci.yml`, triggered on `pull_request` and `push: main`, with no `schedule`. Jobs: `typecheck → lint → unit → build → kind-scan`.
*Acceptance:*
- No `schedule:` key anywhere under `.github/workflows/`.
- No deploy or GHCR-push job.
- Branch protection on `main` requires `ci` (Marcus sets this manually).
- A deliberately broken type or test fails the PR.
- Wall-clock target ≤ 8 min, measured and not assumed.

**R-2 (P0): Cut non-core surface.**
- Delete `performance.service.ts`, its controller and routes.
- Delete `dashboard.service.ts` and the dashboard routes.
- Delete the simulated metrics.
- Delete `k8s/security/pod-security-policy.yaml`.
- Delete the placeholder deploy config.
- Unmount and freeze the auth stack: move it to `src/_frozen/auth/`, excluded from the build, pending D2.
- Remove Mongo and Redis from the runtime path.

*Acceptance:*
- `grep -r "Math.random" src/` returns nothing, except ID generation.
- The app boots with **no** `MONGODB_URI` or `REDIS_URL`.
- `/health` no longer contains "Production Ready" or `capabilities`.

**R-3 (P0): No silent fixtures.**
- Remove all `BASELINE_*` fallbacks from discovery and security.
- On API failure, return a typed error (`K8sUnavailable`).
- Every response carries `source: "live" | "demo"`. Demo mode is enabled only by an explicit `NOIP_DEMO=1` and reads fixtures from `fixtures/demo-cluster.json`.
- `/health` reports `degraded` when Kubernetes is unreachable.

*Acceptance:*
- With no kubeconfig and no `NOIP_DEMO`, `GET /api/discovery/cluster` returns HTTP 503 with `K8sUnavailable`.
- With `NOIP_DEMO=1`, it returns 200 and `source:"demo"`.
- Unit tests mock the k8s client and no longer assert fixture names.

**R-4 (P0): Live verification against kind.**
The CI job creates a `kind` cluster and applies `test/fixtures/misconfig/*.yaml`, which should contain:
- a privileged pod
- a hostPID pod
- a namespace without a NetworkPolicy
- a cluster-admin binding to the default SA
- a pod with a `secretKeyRef` env var

It then runs `noip scan --output report.json` and a clean-namespace control case.

*Acceptance:*
- Each seeded misconfiguration produces exactly the expected finding or control ID (golden file).
- The clean namespace produces none of those.
- `report.json` is uploaded as an artifact.
- NOIP runs under a ServiceAccount with a **read-only ClusterRole**, shipped in `deploy/rbac.yaml`, that has no `secrets` access. Therefore `scanSecrets()` is deleted, and CIS 5.4.1 uses pod specs only, as it already does.

**R-5 (P0): Server actually boots and is protected.**
- Fix ESM resolution. Recommended: `module`/`moduleResolution: NodeNext` plus `.js` import suffixes; the alternative is to bundle with `tsup`.
- Fix `rootDir`/`outDir` so that `dist/app.js` exists.
- Move runtime dependencies into `dependencies`.
- Replace `app.use('*')`.
- Add a bearer-token middleware (`NOIP_API_TOKEN`) on all `/api/*` routes.

*Acceptance:*
- The Docker image builds.
- `docker run` followed by `curl /health` returns 200.
- An `/api/*` request without the token returns 401.
- A CI smoke step covers these checks.

**R-6 (P0): LLM seam with a sane default.**
- Define an `LLMProvider` interface (`complete(prompt, schema)`) with two adapters:
  - `anthropic`, the default. Model comes from `NOIP_LLM_MODEL`, with the default pinned in config and not hardcoded in 5 places.
  - `openai-compatible`, taking `base_url` and `key`. This covers OpenRouter and GLM's OpenAI-compatible endpoint.
- Add a `redact()` step that strips env values, annotations and `data` fields before sending.
- Validate LLM output with zod. On failure, return the deterministic report with `explanation: null`.
- If no key is set, the AI routes return 501 and the scan still works.

*Acceptance:*
- Unit tests with a fake provider cover these cases:
  - redaction, with a snapshot of the outgoing prompt containing no seeded secret value
  - schema failure
  - provider swap through config alone
- An optional, manually dispatched live test job runs against the real provider.

**R-7 (P1): CLI entry point.**
`noip scan [--kubeconfig] [--context] [--output json|md] [--explain]` reuses the services, needs no HTTP server, and works against MicroK8s or Rackspace with a kubeconfig.
*Acceptance:* the kind CI job uses the CLI, and `--output md` renders a human-readable report whose per-finding evidence lines match the JSON.

**R-8 (P1): Honest docs.**
- Rewrite `CLAUDE.md` to match the repo, routes, stack and the phase-loop commands.
- Update the GitHub description.
- Move `RELEASE_NOTES.md`, `RELEASE_SUMMARY_v1.0.0.md`, `qa_pipeline_report.md`, `CLEANUP_REPORT.md`, `DEPLOYMENT_GUIDE.md` and `NOIPPLAN.md` to `docs/archive/` with a banner.
- Update `IMPLEMENTATION_STATUS.md`, marking ADRs superseded by the cuts.

*Acceptance:* a doc-lint step greps for "production-ready", "enterprise-grade" and "/api/v1" outside `docs/archive/` and fails if any are found.

**R-9 (P1): Coverage ratchet on the retained core.**
Coverage covers `src/services/{discovery,security,compliance}` and `src/llm/**` only. Set the threshold to the measured baseline after Phase 2, then raise it toward a **target** of 80% statements on those paths.
*Acceptance:* CI fails if coverage drops below the committed threshold, and the threshold never decreases in any PR.

**R-10 (P1): Report provenance.**
Each report includes:
- the scanner version and git SHA
- cluster server version, taken from the version API rather than kubelet
- a scan timestamp
- the list of checks run
- control mappings labeled "reference mapping, not an attestation"

*Acceptance:* validated by the JSON schema in `schemas/report.schema.json`.

**R-11 (P2): Python scripts decision.**
Per D4, move `scripts/*.py` to `legacy/` or delete them (tag `v1.0.0-archive` first). Delete `generate_dashboard.py` regardless.

**R-12 (P2): Ingest `k8s-netinspect` JSON.**
`noip scan --netinspect <file>` merges CNI diagnostics into the report as a "network" section. NOIP does no diagnosis itself.

**R-13 (P2): Railway preview.**
PR previews run the API with `NOIP_DEMO=1` and a banner. There is no cluster credential on Railway.

## 7. Technical approach

### 7.1 Keep
- The security and compliance check logic
- The discovery client calls
- Express, as a thin API
- The Winston logger
- Helmet and the rate limit
- The ADR folder, with new ADRs for the cuts

### 7.2 Delete or freeze
- **Delete:** performance and dashboard services, simulated metrics, `scanSecrets`, PSP manifest, five workflow files, the placeholder Kubernetes deploy manifests in `k8s/` (replaced by `deploy/rbac.yaml` plus a minimal Deployment), `test_data.json`, `test_inventory/`, `dashboard.html`, and `cf-with-context.sh`.
- **Check for per-repo value before deleting:** `.claude-flow/`, `agents/` and `devpods/` look like Turbo Flow scaffolding (the dirs were not opened).
- **Freeze** auth, Mongo and Redis, pending D2.

### 7.3 New shape
```
src/
  k8s/client.ts        # one KubeConfig factory (today duplicated in 3 services)
  checks/              # security + CIS checks as pure fns over fetched lists → Finding[]
  scan.ts              # fetch once, run all checks, build Report (source, provenance)
  llm/{provider.ts, anthropic.ts, openai-compatible.ts, redact.ts, schema.ts}
  api/app.ts           # /health, /api/scan, /api/report/explain — token-gated
  cli.ts               # noip scan
fixtures/demo-cluster.json
test/fixtures/misconfig/*.yaml, test/golden/report.json
```
Checks become pure functions over the lists the API returns. Today every CIS control re-lists all pods, which means five `listPodForAllNamespaces` calls per benchmark. After the change the API is queried once per scan, and unit tests need no k8s mock beyond fixture lists.

### 7.4 Estate overlap (don't duplicate)

| Sibling | Owns | NOIP stance |
|---|---|---|
| `marcuspat/rustops` | Anomaly detection, alert correlation, event-sourced incidents, Prometheus | NOIP does none of this. Findings could later become rustops events (out of scope). |
| `aops-sre-pipeline` | Prometheus → n8n → LLM → Slack alert narration | NOIP has no alerting and no Slack. |
| `agentic-devops-extravaganza` | k8sgpt on kind | Closest overlap: LLM-explained K8s problems. NOIP differs on three points: posture rather than runtime faults, deterministic control IDs with golden tests, and redacted, schema-validated LLM use. Document this in the README. |
| `marcuspat/k8s-netinspect` | CNI diagnostics | NOIP only ingests its JSON (R-12). |

### 7.5 Config and secrets
| Variable | Required? |
|---|---|
| `NOIP_API_TOKEN` | Required for the API |
| `NOIP_LLM_PROVIDER` | Optional; default `anthropic` |
| `NOIP_LLM_MODEL` | Optional |
| `ANTHROPIC_API_KEY` or `NOIP_LLM_API_KEY` + `NOIP_LLM_BASE_URL` | Optional |
| `NOIP_DEMO` | Optional |
| `KUBECONFIG` | Standard kubeconfig |

CI needs **no** secrets for the required path.

### 7.6 Deploy target
The primary artifact is the CLI plus the CI report. The Railway PR preview (demo mode) is optional (P2). No Vercel.

## 8. Delivery plan
Each phase is one PR, validated by CI, and Marcus merges.

| Phase | PR scope | Validation gate | Done means |
|---|---|---|---|
| **0: Truth run** | No code changes. A Claude Code session installs, typechecks, lints, runs unit/integration tests, builds, runs the Docker image, and measures coverage. It confirms or refutes §2.4 items 2–5 and records results in `docs/REVIVAL_BASELINE.md`. | Session log attached to the PR | Every (S) item marked confirmed or refuted with command output. |
| **1: CI + cut** | R-1, R-2, merge of the disable-schedules intent. Close #5 and #9 and delete stale branches (Marcus approves the closures). | `ci.yml` green; no `schedule:` in the repo | Required check enabled on `main`; app boots without Mongo/Redis. |
| **2: Boots and is gated** | R-5 | CI smoke: Docker build, `/health` 200, 401 without token | Image runs locally in CI. |
| **3: Honest data + live proof** | R-3, R-4, `deploy/rbac.yaml`, checks refactor (§7.3). Re-scope #3, then close it. | kind job passes the golden report; demo/live gating tests | #3 closed; zero fixture fallbacks. |
| **4: LLM seam** | R-6. Close #4 as superseded. | Fake-provider tests; optional manual live job | Model configurable; redaction tested. |
| **5: CLI + provenance** | R-7, R-10 | kind job uses the CLI; schema validation | `noip scan` works against a kubeconfig. |
| **6: Docs + ratchet** | R-8, R-9. Re-scope #6, then close it. | Doc-lint; coverage threshold committed | README, CLAUDE.md and description agree. |
| **7 (P2)** | R-11, R-12, R-13 as chosen | Per item | — |

## 9. Success metrics (targets)
- **CI signal.** Target: 100% of merges to `main` after Phase 1 pass the required `ci` check; no merge bypasses it.
- **Live proof.** Target: the kind golden test detects 5/5 seeded misconfigurations and raises 0 false positives in the clean namespace, on every PR.
- **Honesty.** Target: 0 occurrences of fixture data without `source:"demo"`; 0 banned phrases outside `docs/archive/`.
- **Cost.** Target: 0 scheduled workflow runs; Actions minutes per PR under ~10 (an estimate, to be confirmed in Phase 1).
- **Field use.** Target: at least one scan run against a real non-kind cluster (MicroK8s or Rackspace), with the report attached to a CTM audit or demo, within 30 days of Phase 5.
- **Coverage.** Target: ≥80% statements on retained core paths by the end of Phase 6. This is a target, not a claim.

## 10. Risks and open decisions
Each decision has a recommended default, chosen for lowest risk and cheapest reversal.

- **D1: Name and positioning.** Options:
  - (a) Keep "NetOps Intelligence Platform".
  - (b) Keep the acronym NOIP, retitle it "Kubernetes posture scanner" and fix the description.
  - (c) Rename the repo.

  **Default: (b).** It removes the false claim, is reversible, and breaks no links.
- **D2: The auth stack and MFA (#5).** Options:
  - (a) Wire Twilio/SendGrid.
  - (b) Use an identity provider or proxy (Cloudflare Access or oauth2-proxy) in front.
  - (c) Use a bearer token now and freeze the auth code.

  **Default: (c).** Add (b) only if a hosted multi-user demo is ever needed; delete the frozen code after 90 days if unused. (a) is rejected because it adds paid providers and secrets to a single-operator tool.
- **D3: LLM default.** Options: Anthropic, OpenRouter, or GLM. **Default: Anthropic,** behind the seam, with the `openai-compatible` adapter covering OpenRouter and GLM. It is one code path, and swapping requires config only.
- **D4: Python scripts.** Options: keep in-repo, move to `legacy/`, or delete. **Default: tag `v1.0.0-archive`, then delete.** They duplicate the Rust tools in the estate (file-hasher, secret-scan per NOIPPLAN.md) and share no code with the TS app.
- **D5: Own checks vs. wrapping kube-bench or kubescape.** **Default: keep the own checks,** capped at about 15 controls with golden tests. Revisit if a client needs full CIS coverage, and wrap rather than extend when that happens.
- **D6: Test cluster.** Options: kind, k3s, MicroK8s, or Rackspace. **Default: kind in CI.** It is reproducible and needs no secrets. MicroK8s and Rackspace stay manual field targets via the CLI.
- **Risk: Phase 0 finds more breakage than §2.4 lists.** Mitigation: Phase 0 is read-and-measure only, so the plan can be re-cut before any code changes.
- **Risk: an LLM leaks client data.** Mitigation: `redact()` with snapshot tests, `--explain` opt-in, and a documented no-data-retention provider choice.
- **Risk: the RBAC scope creeps to secrets.** Mitigation: `deploy/rbac.yaml` is golden-tested and must not grant `secrets`.

## 11. Out of scope / explicitly cut
- SMS/email MFA (#5)
- User and role management UI
- Mongo/Redis persistence
- Refresh-token replay detection and the Redis rate-limit store (ADR-0005/0006/0014)
- The `/api/v1` versioning migration (ADR-0020); `/api` stays until there are external clients
- AgentDB/ReasoningBank ports (ADR-0011)
- DDD aggregate build-out (ADR-0013)
- Load testing and the `PerformanceService`
- Random-data dashboards
- The Prometheus/Grafana manifests
- Multi-arch GHCR publishing
- Staging and production deploy jobs
- Slack notifications
- Scheduled scans of any kind
- Network traffic analytics, anomaly detection and incident response (see §7.4)
