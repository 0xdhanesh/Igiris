#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash -n packaging/install.sh packaging/reinstall.sh
python -m pip install build==1.3.0
python -m build
wheel_env="$(mktemp -d /tmp/igiris-wheel.XXXXXX)"
trap 'rm -rf "$wheel_env"' EXIT
python -m venv "$wheel_env"
"$wheel_env/bin/pip" install dist/*.whl
"$wheel_env/bin/python" -c 'import igiris'
"$wheel_env/bin/igiris-set-password" --help >/dev/null
