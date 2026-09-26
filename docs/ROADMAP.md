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

## Later
These are candidates, not commitments:
- Per-namespace Pod Security Admission label check (this would be check #15, which hits the cap).
- OpenVEX-style exception export.
- Signed release artifacts with SLSA provenance, once releases exist.
