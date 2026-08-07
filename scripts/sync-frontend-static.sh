#!/usr/bin/env bash
# Build the Vite UI (optional) and replace src/igris/static with frontend/dist.
# Used by local development and GitHub Actions so packaged assets stay identical.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_INSTALL=0
SKIP_BUILD=0

usage() {
  cat <<'EOF'
Usage: scripts/sync-frontend-static.sh [--skip-install] [--skip-build]

  --skip-install  Do not run npm ci (dependencies already installed)
  --skip-build    Do not run npm run build (frontend/dist already current)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install) SKIP_INSTALL=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  cd "$ROOT/frontend"
  if [[ "$SKIP_INSTALL" -eq 0 ]]; then
    npm ci
  fi
  npm run build
fi

if [[ ! -d "$ROOT/frontend/dist" ]]; then
  echo "ERROR: frontend/dist is missing; build the frontend first." >&2
  exit 1
fi

rm -rf "$ROOT/src/igris/static"
mkdir -p "$ROOT/src/igris/static"
cp -a "$ROOT/frontend/dist/." "$ROOT/src/igris/static/"
diff -qr "$ROOT/frontend/dist" "$ROOT/src/igris/static"
echo "src/igris/static is synchronized with frontend/dist"
