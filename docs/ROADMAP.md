# Roadmap: state-of-the-art improvements

The improvement loop works through this list top-down, one stacked PR per item. Each item gets its own entry below; the status line in each says whether it has shipped.

## 1. SARIF 2.1.0 output
Status: shipped (`loop/r1-sarif`)

**Why:** SARIF is the interchange format that kubescape, Trivy and Checkov all emit. Supporting it lets findings flow into GitHub code scanning, DefectDojo and IDEs without any custom glue.

## 2. Shift-left manifest scanning
Status: shipped (`loop/r2-manifests`)

The command is `noip scan --manifests <path>`. It runs the same pure checks over YAML from files, directories, stdin, or rendered `helm template` / `kustomize build` output. Pod templates in workload resources are expanded, and findings point at `file:line`.

**Why:** misconfigurations get caught in the PR, before they reach a cluster. This comes almost for free because the checks are already pure functions over a snapshot.

## 3. Suppressions with accountability
Status: shipped (`loop/r3-suppressions`)

Suppressions live in a `.noip-ignore.yaml` file. Each entry needs a finding ID or check-plus-resource glob, a `reason`, an `owner` and an `expires` date. Suppressed findings are kept in the report under `suppressed[]`, with the reason attached. When a suppression expires, the finding becomes active again and a warning is printed.

This round also pins GitHub Actions to commit SHAs.

**Why:** adoption on real clusters needs accepted-risk handling, and expiry stops suppressions from quietly becoming permanent. SHA pinning is OpenSSF Scorecard hygiene.

## 4. MCP server
Status: shipped (`loop/r4-mcp`)

Running `noip mcp` starts a stdio MCP server exposing three tools: `scan`, `list_checks` and `explain_finding`. All are read-only, use the same kubeconfig and RBAC, and return structured content that follows the report schema.

**Why:** agents (Claude Code, Turbo Flow) can run a posture audit as a tool call and reason over deterministic findings rather than raw `kubectl` output.

## 5. Posture drift: `noip diff`
Status: shipped (`loop/r5-diff`)

`noip diff a.json b.json` compares two reports and lists new, resolved and changed findings, newly suppressed findings, control flips and the score delta. `--fail-on` exits non-zero when a new finding is at or above the given severity.

**Why:** reliability retainers need to show the trend between scans, not a one-off snapshot.

## 6. Independent review fixes
Status: shipped (`loop/r6-review-fixes`)

A separate reviewer agent audited the stack and found eight defects. All eight are now fixed and each has a regression test (`test/review-fixes.test.ts`):

1. Ephemeral containers were not scanned.
2. RoleBindings that grant `cluster-admin` were missed.
3. `NOIP_DEMO` silently overrode `--manifests`.
4. MCP tools accepted arbitrary kubeconfig paths, even though kubeconfigs can run `exec` plugins, and arbitrary manifest paths.
5. Finding IDs changed on every run for Jobs created by a CronJob.
6. Deduplication dropped manifests that use `generateName`.
7. The MCP `minSeverity` filter left the summary inconsistent with the findings.
8. SARIF output used `<stdin>` as a file URI.

The review also raised two minor issues, which are fixed as well: overlapping suppressions were reported as stale, and egress to `0.0.0.0/0` was not flagged.

## 7. Pod Security Admission enforcement check
Status: shipped (`loop/r7-psa`)

NOIP-NS-001 flags a namespace that doesn't enforce the Pod Security Admission `baseline` or `restricted` profile. It's the 15th check, so the set is now at its cap.

On kind, the clean namespace now enforces `restricted` for real. That also proves its pods are admissible under that profile.

**Why:** a scan only finds what's already running, while admission control stops a misconfigured pod before it starts. From here on, a new check has to replace or wrap an existing one (ADR-0004).

## Loop 2 (2026-09-26, 12 rounds)

| # | Item | Status |
|---|---|---|
| 8 | Supply chain: CycloneDX SBOM, license allowlist, `npm audit` for vulnerabilities and signatures, Docker `--ignore-scripts` | shipped (`loop/r8-supply-chain`) |
| 9 | Self-contained HTML report | shipped (`loop/r9-html`) |
| 10 | Audit evidence bundle: SHA256SUMS and an in-toto provenance statement, plus `noip verify-bundle` | shipped (`loop/r10-bundle`) |
| 11 | Remediation patches (JSON Patch per finding) and `noip fix` for manifests, preserving comments | shipped (`loop/r11-fix`) |
| 12 | Import third-party SARIF (Trivy, kubescape, Checkov) into one report, without changing NOIP's score | shipped (`loop/r12-import-sarif`) |
| 13 | Multi-context (fleet) scans: one report per cluster, `fleet.json`/`fleet.md`, and an unreachable cluster doesn't stop the run | shipped (`loop/r13-multi-context`) |
| 14 | Paginated LIST (limit/continue, restart on 410) and a scale benchmark (10k pods in about 0.3 s) | shipped (`loop/r14-scale`) |
| 15 | Property-based and fuzz tests (fast-check). These found and fixed a manifest-parser crash on unresolved aliases, and the parser now also has a bound on alias expansion. | shipped (`loop/r15-property-tests`) |
| 16 | OpenAPI 3.1 spec (`/openapi.json`), plus contract tests that check every route's responses against it | shipped (`loop/r16-openapi`) |
| 17 | NSA/CISA Hardening Guide and NIST SP 800-190 reference mappings for every check, in all output formats and in MCP | shipped (`loop/r17-mappings`) |
| 18 | Second independent review: 5 defects plus 2 minor issues found and fixed, each with a regression test (`test/review2-fixes.test.ts`). The fixes cover `noip fix` securityContext merging and findings it couldn't locate, markdown injection from imported SARIF, fleet file-name collisions, `verify-bundle` following symlinks and accepting non-subject files, the NS-001 labels parent, and an `--out-dir` inside the input. The scale test also exposed per-finding glob recompilation, now cached. | shipped (`loop/r18-review2-fixes`) |
| 19 | Wrap-up: CLAUDE.md, REQUIREMENTS.md and README brought up to date | shipped (`loop/r19-wrapup`) |

## Loop 3 (2026-09-26 afternoon)

| # | Item | Status |
|---|---|---|
| 20 | Stack health: every branch head checked the way CI would; `npm run ci:local` | shipped (`loop/r20-ci-local`) |
| 21 | Deterministic executive summary / "fix these first": severity, then blast radius, then reach; quick wins vs design decisions | shipped (`loop/r21-exec-summary`) |
| 22 | Spanish reports (`--lang es`) for markdown, HTML, bundles and fleet runs. English output is byte-identical. The fuzzer also found a redaction gap here: tokens ending in `-`/`_`. Now fixed. | shipped (`loop/r22-i18n-es`) |
| 23 | Kubernetes version support facts from the kubernetes.io/releases table (as of 2026-09-26): end of life, ending soon, newer patch available; not a check | shipped (`loop/r23-version-support`) |
| 24 | Posture history and trend (`noip history`) | planned |
| 25 | Policy-as-code export: ValidatingAdmissionPolicy (CEL) | planned |
| 26 | Distribution: composite GitHub Action and pre-commit hook | planned |
| 27 | Independent review #3, with fixes | planned |
| 28 | Wrap-up | planned |

## Later
These are candidates, not commitments:
- OpenVEX-style exception export.
- Signed release artifacts with SLSA provenance, once releases exist.
