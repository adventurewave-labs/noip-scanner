# Changelog

## v0.2.0 — 2026-09-29

This is the first release of `noip-scanner`, a read-only Kubernetes posture scanner that replaces `adventurewave-labs/NOIP`. It collects PRs #1–#47. CI passes on the release commit, including the live scan against a kind cluster, the Docker smoke test and the composite-action job.

### Scanner
- It runs 15 deterministic checks: pod security, Pod Security Admission labels, NetworkPolicy, and RBAC. Findings map to CIS controls and to NSA/CISA and NIST SP 800-190 references.
- It scans a live cluster (read-only RBAC, never `secrets`), offline manifests (`noip scan <paths>`), several clusters at once (`--contexts` / `--all-contexts`), or the demo fixture.
- If the cluster is unreachable, the scan fails with `K8sUnavailable` (exit 3, HTTP 503). It never substitutes silent fixture data.
- Accepted-risk suppressions carry a reason, an owner and an expiry.
- `--min-severity` filters findings. `--fail-on` gates CI, and `--baseline` makes the gate fail only on findings that are new since an earlier report.

### Reports and analysis
- Output formats: JSON (schema-validated), Markdown, HTML, SARIF 2.1.0 (with `baselineState`), OSCAL 1.2.3 assessment results, and a CycloneDX 1.6 KBOM.
- Markdown and HTML reports are available in English and Spanish (`--lang es`).
- Reports include an executive summary, Kubernetes end-of-life and patch status, and **Pod Security readiness**. Readiness is a port of the upstream PSA checks and passes all 820 upstream conformance fixtures.
- **Risk chains** show where findings compound. Examples: a workload carrying a cluster-admin token, default-ServiceAccount role inheritance, and externally exposed workloads with host access.
- Commands for working with reports: `noip diff`, `noip history` (score trend, with an HTML chart), and `noip render` (re-render a saved report).
- Evidence bundles contain SHA256SUMS and an in-toto statement. They can optionally be signed as a DSSE envelope, and cosign can verify the signature. Check a bundle with `noip verify-bundle`.

### Remediation and policy
- `noip fix` applies deterministic RFC 6902 fixes to YAML and keeps comments. For the Pod Security label it only picks a level that every current pod already meets.
- `noip policy` exports ValidatingAdmissionPolicy (CEL) YAML. Parity with the checks is tested, and the policies are applied to a real API server in CI.

### Integrations
- An HTTP API under `/api` with bearer auth, an OpenAPI 3.1 document, and Prometheus metrics at `/api/metrics`.
- An MCP server with six read-only tools.
- A GitHub composite action and a pre-commit hook.
- An optional LLM explanation. Its input is redacted and its output is schema-validated; the LLM never decides anything.

### Upgrade notes
- **Re-apply `deploy/rbac.yaml`.** Live scans now also list ServiceAccounts and Services. Without the new permissions every live scan fails with `K8sUnavailable`.

### Fixed before release
- Six independent reviews found defects, and each fix has a regression test.
- The first real kind run found that admission rules errored on a plain CREATE (`request.subResource` is absent there) and were silently skipped under `failurePolicy: Ignore`. Fixed in #47.
