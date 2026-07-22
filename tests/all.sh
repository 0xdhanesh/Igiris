#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/tests/python.sh"
"$ROOT/tests/frontend.sh"
"$ROOT/tests/package.sh"
printf 'Local CI checks passed. Run test/security.sh separately for security audits.\n'
