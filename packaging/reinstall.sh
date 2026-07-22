#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo packaging/reinstall.sh" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=igiris

printf 'Stopping %s service...\n' "$SERVICE"
systemctl stop "$SERVICE" 2>/dev/null || true

printf 'Installing the latest repository version into /opt/igiris...\n'
"$ROOT/packaging/install.sh"

printf 'Restarting %s service...\n' "$SERVICE"
systemctl restart "$SERVICE"

cat <<'EOF'

Reinstallation complete. Check the service with:

  sudo systemctl status igiris
  sudo journalctl -u igiris -n 100 --no-pager

For live logs:

  sudo journalctl -u igiris -f
EOF
