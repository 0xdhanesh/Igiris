#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/frontend"
npm ci
npm test
npm run build
cd "$ROOT"
# Local gate: committed static must match the build. On GitHub, the
# "Sync frontend static" workflow auto-commits drift; CI packages the
# build artifact even if the tree was briefly stale.
if ! diff -qr frontend/dist src/igris/static; then
  echo "ERROR: src/igris/static is stale. Sync with:"
  echo "  bash scripts/sync-frontend-static.sh --skip-install --skip-build"
  echo "  git add src/igris/static && git commit -m 'chore: sync packaged frontend static assets'"
  exit 1
fi
