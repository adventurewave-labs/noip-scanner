#!/usr/bin/env bash
# Run every CI gate that does not need Docker or a cluster, in CI order, from a clean dist/.
# Use when GitHub Actions is unavailable. The kind and docker-smoke jobs still need a Docker host:
#   NOIP_CI_DOCKER=1 scripts/ci-local.sh   also runs them if `docker` and `kind` are on PATH.
set -uo pipefail
cd "$(dirname "$0")/.."
failed=()
skipped=()
step() { local name=$1; shift; printf '\n== %s\n' "$name"; if "$@"; then echo "   ok"; else echo "   FAILED"; failed+=("$name"); fi; }

rm -rf dist coverage
step typecheck        npm run -s typecheck
step lint             npm run -s lint
step doc-lint         bash scripts/doc-lint.sh
step "unit+coverage"  npx vitest run --coverage
if git rev-parse -q --verify "${NOIP_BASE_REF:-origin/main}" >/dev/null; then
  step ratchet        node scripts/check-ratchet.mjs "${NOIP_BASE_REF:-origin/main}"
else
  printf '\n== ratchet\n   SKIPPED: base ref %s not found (set NOIP_BASE_REF)\n' "${NOIP_BASE_REF:-origin/main}"; skipped+=(ratchet)
fi
step build            npm run -s build
step "demo report schema" bash -c 'node --no-deprecation dist/cli.js scan --demo --out /tmp/noip-demo.json 2>/dev/null && node scripts/validate-report.mjs /tmp/noip-demo.json'
step "manifest golden"    bash -c 'node --no-deprecation dist/cli.js scan --manifests test/fixtures/misconfig --out /tmp/noip-m.json 2>/dev/null && node scripts/validate-report.mjs /tmp/noip-m.json && node scripts/golden-compare.mjs /tmp/noip-m.json --source manifests'
step "mcp stdio smoke"    node scripts/mcp-smoke.mjs
step "npm audit (runtime, high+)" npm audit --omit=dev --audit-level=high
step "sbom + licenses"    node scripts/supply-chain.mjs /tmp/noip-sbom.cdx.json

if [ "${NOIP_CI_DOCKER:-0}" = 1 ]; then
  if command -v docker >/dev/null && command -v kind >/dev/null; then
    step "docker build" docker build --build-arg NOIP_GIT_SHA="$(git rev-parse HEAD)" -t noip:local .
    echo "   (kind golden: see the kind-scan job in .github/workflows/ci.yml; run its steps against 'kind create cluster')"
  else
    echo; echo "== docker/kind requested but not on PATH"; failed+=("docker/kind")
  fi
else
  printf '\n== skipped: kind-scan, docker-smoke (need a Docker host; NOIP_CI_DOCKER=1 to try)\n'
fi

echo
if [ ${#failed[@]} -eq 0 ]; then echo "ci-local: ALL GATES PASSED${skipped[*]:+ (skipped: ${skipped[*]})}"; else echo "ci-local: FAILED: ${failed[*]}"; exit 1; fi
