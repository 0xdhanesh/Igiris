#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/frontend"
npm ci
npm test
npm run build
cd "$ROOT"
diff -qr frontend/dist src/igris/static
