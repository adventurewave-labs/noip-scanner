# Security

NOIP is a read-only tool, and its own security posture has four parts:

- **RBAC:** its RBAC (`deploy/rbac.yaml`) grants `get`/`list` on namespaces, pods, nodes, NetworkPolicies and (Cluster)RoleBindings only. It grants nothing on `secrets`, and `test/rbac.test.ts` checks this.
- **Evidence:** reports cite field paths plus the names and keys of secrets. They never include secret values, and the kind golden test checks that a seeded secret value is absent from the report.
- **LLM:** LLM calls are opt-in (`--explain`), and inputs are redacted first (`src/llm/redact.ts`).
- **API:** the API requires a bearer token and refuses to start without one.

To report a vulnerability, contact the maintainers privately rather than opening a public issue.
