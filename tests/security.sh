#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
gitleaks detect --no-git
python -m pip install --upgrade pip==26.2 setuptools==83.0.0
python -m pip install pip-audit==2.10.1
python -m pip_audit --local
python -m pip install bandit==1.9.4 semgrep==1.172.0 zizmor==1.28.0
SEMGREP_SEND_METRICS=off semgrep scan --config p/security-audit --config p/secrets --exclude .venv --exclude frontend/node_modules --exclude frontend/dist --exclude src/igris/static .
bandit -r src/igris --severity-level high --confidence-level medium
( cd frontend && npm ci && npm audit --audit-level=high )
zizmor .github/workflows
