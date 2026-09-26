# PRD requirement traceability

This table maps each PRD requirement to where it lives in the code and what verifies it. Status reflects the state of the initial build PR.

| Req | Where | Verified by |
|---|---|---|
| **R-1** Single CI workflow | `.github/workflows/ci.yml` (jobs `verify → kind-scan, docker-smoke → ci`); no `schedule:`, no deploy, no image push | CI run on the build PR. Branch protection requiring `ci` is a manual step for the owner. |
| **R-2** Cut non-core surface | Holds by construction: nothing simulated, no auth DB, no Mongo/Redis, no PSP, no placeholder deploys (ADR-0001) | `grep -r "Math.random" src/` returns nothing; `/health` has no "capabilities" (`test/api.test.ts`) |
| **R-3** No silent fixtures | `src/k8s/snapshot.ts`, `src/scan.ts#getSnapshot`, `src/api/app.ts` | `test/api.test.ts` covers 503 `K8sUnavailable` with no kubeconfig, 200 + `source:"demo"` with `NOIP_DEMO`, and `degraded` health; the docker-smoke job |
| **R-4** Live verification on kind | `test/fixtures/misconfig/`, `test/golden/kind-findings.json`, `scripts/golden-compare.mjs`, `deploy/rbac.yaml`, `scripts/sa-kubeconfig.sh` | The kind-scan job (report artifact uploaded); `test/golden.test.ts` offline; `test/rbac.test.ts` |
| **R-5** Boots and is protected | NodeNext + `.js` imports, `rootDir: src` → `dist/api/server.js`, runtime deps in `dependencies`, Express 5 catch-all, bearer middleware | docker-smoke (build, `/health` 200, 401 without token); `test/api.test.ts` |
| **R-6** LLM seam | `src/llm/*` | `test/llm.test.ts` (redaction snapshot, schema failure, provider swap); `test/anthropic.test.ts`; manual `llm-live` job |
| **R-7** CLI | `src/cli.ts` | `test/cli.test.ts`; the kind job scans through the CLI; md evidence lines equal JSON (`test/report.test.ts`) |
| **R-8** Honest docs | README, CLAUDE.md, ADRs, `scripts/doc-lint.sh` | The doc-lint step in `verify`. The GitHub description is set on repo creation. |
| **R-9** Coverage ratchet | `vitest.config.ts` (core paths only), `coverage-thresholds.json`, `scripts/check-ratchet.mjs` | The `verify` job fails below threshold, and fails if a PR lowers a threshold. The 80% statement target is already exceeded at baseline. |
| **R-10** Report provenance | `src/report/provenance.ts`, `src/scan.ts`, `schemas/report.schema.json` | `test/report.test.ts`; schema validation in `verify` and `kind-scan` |
| **R-11** Python scripts | Not ported (ADR-0001). The old repo keeps them. | n/a |
| **R-12** Ingest netinspect | `src/report/netinspect.ts`, `schemas/netinspect-input.schema.json` | `test/report.test.ts`, `test/cli.test.ts`. Note that k8s-netinspect has no JSON output yet; this schema is the contract. |
| **R-13** Railway preview | `railway.json`, demo banner at `GET /`, `X-NOIP-Mode: demo` header | `test/api.test.ts`; the demo step in docker-smoke. Connecting the Railway service to the repo is a manual step. |

## Beyond the PRD: improvement loops

These features go past the PRD's requirements. `docs/ROADMAP.md` gives the reasoning behind each one.

| Feature | Where | Verified by |
|---|---|---|
| SARIF 2.1.0 | `src/report/sarif.ts` | Tests against the official OASIS schema (`test/sarif.test.ts`) |
| Offline manifest scanning | `src/manifests.ts` | Offline scan matches the same golden file as kind; fuzzing (`test/properties.test.ts`) |
| Suppressions with expiry | `src/suppressions.ts` | `test/suppressions.test.ts`; partition property |
| MCP server | `src/mcp.ts` | In-memory transport tests; stdio smoke test in CI |
| Posture drift | `src/report/diff.ts` | `test/diff.test.ts`; "diffing a report with itself gives nothing" property |
| PSA check (15/15) | `src/checks/namespace.ts` | kind: the restricted namespace actually admits the hardened pods |
| Supply chain | `scripts/supply-chain.mjs`, CI `supply-chain` job | npm audit (vulnerabilities and signatures); SBOM artifact; license allowlist |
| HTML report | `src/report/html.ts` | HTML injection tests; rendered checks for mobile and dark mode |
| Evidence bundle | `src/report/bundle.ts` | Tamper, symlink and extra-file tests; `sha256sum -c` compatible |
| Fixes | `src/remediation.ts`, `src/fix.ts` | Re-scan after fixing leaves only findings that need judgement; fixing twice changes nothing |
| SARIF import | `src/report/import-sarif.ts` | Score unchanged; SARIF output still valid; markdown injection tests |
| Fleet scans | `src/fleet.ts` | Unreachable clusters are recorded and the scan continues; file-name collision tests |
| Scale | `listAll()` in `src/k8s/snapshot.ts` | Pagination and 410-restart tests; 10k-pod time budget (`test/scale.test.ts`) |
| OpenAPI 3.1 | `src/api/openapi.ts` | Document validates; every route is documented; responses conform |
| NSA/CISA and NIST 800-190 references | `src/checks/references.ts` | Completeness test covering every check |
| Two independent reviews | `test/review-fixes.test.ts`, `test/review2-fixes.test.ts` | A regression test for each defect found |
| Posture history | `src/report/history.ts`, `noip history` | Grouping, scope-change and escaping tests (`test/history.test.ts`) |
| Admission policies | `src/policy.ts`, `noip policy` | CEL/check parity on fixtures and random pods (`test/policy.test.ts`); kind job applies them (warn and deny) |
| GitHub Action and pre-commit hook | `action.yml`, `.pre-commit-hooks.yaml`, `scripts/pre-commit-noip.sh` | Pinning and injection tests (`test/distribution.test.ts`); CI `action-smoke` job |
| Third independent review | `test/review3-fixes.test.ts` | A regression test for each confirmed defect |
| Pod Security readiness | `src/psa.ts`, report `podSecurity` | Upstream PSA conformance fixtures, 1.23–1.37 (`test/psa.test.ts`) |
| OSCAL assessment results | `src/report/oscal.ts`, `-o oscal`, bundle `report.oscal.json` | Official OSCAL 1.2.3 schema validation; deterministic UUIDv5 known-answer test (`test/oscal.test.ts`) |
| Signed evidence bundles | `src/report/dsse.ts`, `--sign-key`, `verify-bundle --key` | DSSE PAE spec vector, tamper/re-sign tests (`test/dsse.test.ts`); manual cosign v2.6.5 cross-check |
| Prometheus metrics | `src/api/metrics.ts`, `GET /api/metrics` | Exposition parsing, label escaping, TTL / single-flight / backoff tests (`test/metrics.test.ts`); OpenAPI route coverage |
| Fourth independent review | `test/review4-fixes.test.ts`, `test/metrics.test.ts` | A regression test for each confirmed defect |
