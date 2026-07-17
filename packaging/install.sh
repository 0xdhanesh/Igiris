#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Run as root: sudo packaging/install.sh" >&2; exit 1; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -d -m 0755 /opt/igiris /etc/igiris
PASSWORD_FILE=/etc/igiris/password.verifier
python3 -m venv --system-site-packages /opt/igiris/.venv
/opt/igiris/.venv/bin/pip install "$ROOT"
if [[ ! -s "$PASSWORD_FILE" ]]; then
  printf 'Create the local Igiris unlock password (minimum 12 characters).\n'
  /opt/igiris/.venv/bin/igiris-set-password --file "$PASSWORD_FILE"
else
  chmod 0600 "$PASSWORD_FILE"
  printf 'Existing Igiris password verifier retained.\n'
fi
install -m 0644 "$ROOT/packaging/igiris.env" /etc/igiris/igiris.env
install -m 0644 "$ROOT/packaging/igiris.service" /etc/systemd/system/igiris.service
systemctl daemon-reload
systemctl enable igiris
if systemctl is-active --quiet igiris; then
  systemctl restart igiris
else
  systemctl start igiris
fi
printf 'Igiris installed. Open http://127.0.0.1:8787 and enter your password.\n'
