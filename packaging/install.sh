#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Run as root: sudo packaging/install.sh" >&2; exit 1; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -d -m 0755 /opt/igiris /etc/igiris
TOKEN_FILE=/etc/igiris/api.token
NEW_TOKEN=false
if [[ ! -s "$TOKEN_FILE" ]]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$TOKEN_FILE"
  chmod 0600 "$TOKEN_FILE"
  NEW_TOKEN=true
fi
python3 -m venv --system-site-packages /opt/igiris/.venv
/opt/igiris/.venv/bin/pip install "$ROOT"
install -m 0644 "$ROOT/packaging/igiris.env" /etc/igiris/igiris.env
install -m 0644 "$ROOT/packaging/igiris.service" /etc/systemd/system/igiris.service
systemctl daemon-reload
systemctl enable --now igiris
printf 'Igiris installed. Open http://127.0.0.1:8787\n'
if [[ "$NEW_TOKEN" == true ]]; then
  printf 'API token (store securely; shown once): %s\n' "$(<"$TOKEN_FILE")"
else
  printf 'Existing API token retained. Retrieve with: sudo cat %s\n' "$TOKEN_FILE"
fi
