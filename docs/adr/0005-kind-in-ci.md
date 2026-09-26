# ADR-0005: kind for live verification

- **Status:** accepted, 2026-09-25
- **Decides:** PRD §10 D6

The `kind-scan` CI job is the live proof. Its steps:

1. Create a kind cluster.
2. Apply `deploy/rbac.yaml` and the seeded fixtures.
3. Mint a kubeconfig for the read-only `noip` ServiceAccount, and assert that it cannot read secrets.
4. Scan with the CLI.
5. Compare the result against `test/golden/kind-findings.json`.

The job needs no secrets. MicroK8s and managed clusters stay manual field targets, reached with `scripts/sa-kubeconfig.sh` and the CLI.
