# NOIP scanner — context for Claude Code

This is a read-only Kubernetes posture scanner, built as a TypeScript CLI with a thin Express API. The spec is `docs/PRD.md`, and requirement traceability is in `docs/REQUIREMENTS.md`.

- **Stack:** Node 22, TypeScript 5.9 (`module`/`moduleResolution: NodeNext`, `.js` import suffixes), Express 5, `@kubernetes/client-node` 1.x, zod, vitest.
- **Repo:** `adventurewave-labs/noip-scanner`. It replaces `adventurewave-labs/NOIP`, from which only the check logic was ported.

## Layout

```
src/k8s/client.ts        single KubeConfig factory
src/k8s/snapshot.ts      fetch every list once → ClusterSnapshot; any failure → K8sUnavailable
src/checks/              pure checks (snapshot → findings); registry in index.ts; CIS catalog in controls.ts
src/scan.ts              buildReport (pure), getSnapshot (live | explicit demo), scan
src/report/              renderers (markdown, html, sarif, oscal), bundle (evidence + verify; optional DSSE signing in dsse.ts), diff, history, import-sarif, netinspect, provenance
src/llm/                 provider seam, anthropic + openai-compatible adapters, redact, zod schema, explain
src/api/                 app.ts (routes, bearer auth), server.ts (entry), metrics.ts (Prometheus exposition)
src/cli.ts               `noip scan | render | diff | history | policy | fix | verify-bundle | mcp`
src/policy.ts            ValidatingAdmissionPolicy (CEL) export; parity-tested against the checks
src/manifests.ts         offline YAML → ClusterSnapshot (shift-left)
src/remediation.ts       deterministic RFC 6902 fixes per finding; src/fix.ts applies them to YAML
src/suppressions.ts      accepted-risk entries (reason/owner/expiry)
src/fleet.ts             multi-context scans (one report per cluster + fleet summary)
src/mcp.ts               MCP server: scan, list_checks, explain_finding, pod_security_readiness, risk_chains, admission_policy (read-only)
src/api/openapi.ts       OpenAPI 3.1 document (/openapi.json); contract-tested
src/checks/references.ts NSA/CISA + NIST SP 800-190 reference mappings
src/chains.ts            risk chains (findings that compound: SA tokens + RBAC); not a check
src/psa.ts               Pod Security Standards (port of upstream PSA checks) + per-namespace readiness; not a check
test/fixtures/psa/                  upstream PSA conformance fixtures (Apache-2.0, vendored unmodified)
fixtures/demo-cluster.json          demo-mode data (fictional)
test/fixtures/misconfig/*.yaml      seeded kind fixtures
test/golden/kind-findings.json      expected finding IDs for those fixtures
deploy/rbac.yaml                    read-only ClusterRole (golden-tested: no secrets)
action.yml, .pre-commit-hooks.yaml  distribution (composite action; script hook → scripts/pre-commit-noip.sh)
```

## Rules

1. **No silent fixtures.** A live failure throws `K8sUnavailable` (HTTP 503, CLI exit code 3). Demo data only comes from `NOIP_DEMO=1` or `--demo`, and it always carries `source: "demo"`.
2. **Checks are pure and capped.** A new check means a new entry in `src/checks/`, unit tests with positive and negative cases, a README table row, and, if it applies to the seeded fixtures, updates to `test/golden/kind-findings.json`. Keep the total at 15 or fewer (ADR-0004).
3. **Evidence never contains secret values.** Record names and keys only. NOIP has no `secrets` RBAC, and `deploy/rbac.yaml` must never gain it.
4. **The LLM explains; it never decides.** Everything sent to it goes through `llmPayload()`/`redact()`. Its output is zod-validated, and on failure the explanation is `null`.
5. **Honest docs.** `npm run doc-lint` bans overselling phrases and the non-existent versioned API prefix outside `docs/archive/`. The API lives under `/api`.
6. **Coverage only ratchets up.** You may raise `coverage-thresholds.json`, never lower it. CI compares it against the base branch.
7. **CI is `.github/workflows/ci.yml` only.** Never add a `schedule:`, a deploy job, or an image push. Actions are pinned to commit SHAs; keep them pinned.
8. **Untrusted text is escaped at the renderer.** Markdown uses `mdSafe()`/`code()`, HTML uses `esc()`. Anything from manifests, imported SARIF or an LLM is untrusted.
9. **Property tests guard invariants.** If `test/properties.test.ts` finds a counterexample, fix the code, not the property. fast-check prints the seed so the failure can be reproduced.

## Commands

```bash
npm ci
npm run typecheck      # tsc --noEmit
npm run lint           # eslint
npm run doc-lint       # banned phrases
npm test               # vitest
npm run coverage       # vitest + thresholds from coverage-thresholds.json
npm run build          # tsc → dist/, writes dist/build-info.json (git SHA)
node dist/cli.js scan --demo -o md
node scripts/validate-report.mjs report.json
node scripts/golden-compare.mjs report.json        # against a live kind scan of test/fixtures/misconfig
```

## Phase loop

Each change is one PR, validated by CI, and Marcus merges. Run the full command list above before pushing. If you change fixtures or checks, run `npx vitest run test/golden.test.ts` first; it's the offline twin of the kind job.
