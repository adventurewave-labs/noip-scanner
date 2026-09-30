# ADR-0004: Own checks, capped at about 15

- **Status:** accepted, 2026-09-25
- **Decides:** PRD §10 D5

NOIP ships its own 14 checks with golden tests, not a wrapper around kube-bench or kubescape. Every check is a pure function, so each one is unit-testable without a cluster and produces evidence that cites a specific field. `test/checks.test.ts` enforces a cap of 15. If a client needs full CIS coverage, wrap an established scanner and merge its output. Do not extend this set.
