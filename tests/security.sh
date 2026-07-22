#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
gitleaks detect --no-git
python -m pip install bandit==1.9.4 semgrep==1.170.0 pip-audit==2.10.1 zizmor==1.27.0
SEMGREP_SEND_METRICS=off semgrep scan --config p/security-audit --config p/secrets --exclude .venv --exclude frontend/node_modules --exclude frontend/dist --exclude src/igiris/static .
bandit -r src/igiris --severity-level high --confidence-level medium
python -m pip_audit --local
( cd frontend && npm ci && npm audit --audit-level=high )
zizmor .github/workflows
