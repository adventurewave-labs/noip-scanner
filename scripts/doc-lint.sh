#!/usr/bin/env bash
# PRD R-8: overselling phrases and the non-existent /api/v1 prefix are banned outside docs/archive/.
# docs/PRD.md is exempt because it quotes the old repo's claims in order to retire them.
set -euo pipefail
cd "$(dirname "$0")/.."
pattern='production[- ]ready|enterprise[- ]grade|(^|[^[:alnum:].-])/api/v1'
if matches=$(git ls-files -z | grep -zv -e '^docs/archive/' -e '^docs/PRD.md$' -e '^scripts/doc-lint.sh$' -e '^package-lock.json$' \
  | xargs -0 grep -nIiE "$pattern" 2>/dev/null); then
  echo "doc-lint: banned phrases found:"
  echo "$matches"
  exit 1
fi
echo "doc-lint: OK"
