#!/usr/bin/env bash
# pre-commit entry point (language: script). Builds NOIP once inside pre-commit's clone of this
# repo, then scans the staged files passed as arguments. Needs Node 22+ and npm on PATH.
# (language: node installs hooks with `npm install -g git+file://…`, and npm's git-dependency
# preparation races with the global install for packages that need a build step, so we build here.)
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ ! -f "$root/dist/cli.js" ]; then
  echo "noip: first run, building the scanner (one-off)…" >&2
  (cd "$root" && npm ci --no-audit --no-fund --ignore-scripts --loglevel=error >&2 && npm run -s build >&2)
fi
exec node --no-deprecation "$root/dist/cli.js" scan "$@"
