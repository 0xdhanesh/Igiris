#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Run as root: sudo packaging/install.sh" >&2; exit 1; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v npm >/dev/null 2>&1; then
  printf 'Error: npm is required to compile the frontend. Install Node.js/npm, then rerun this installer.\n' >&2
  exit 1
fi
printf 'Compiling the latest frontend bundle...\n'
npm --prefix "$ROOT/frontend" ci
npm --prefix "$ROOT/frontend" run build
rm -rf "$ROOT/src/igiris/static"
install -d -m 0755 "$ROOT/src/igiris/static"
cp -a "$ROOT/frontend/dist/." "$ROOT/src/igiris/static/"
KERNEL_RELEASE="$(uname -r)"
if [[ ! -e "/lib/modules/${KERNEL_RELEASE}/build" && ! -e /sys/kernel/kheaders.tar.xz ]]; then
  printf 'Warning: matching headers for running kernel %s are unavailable.\n' "$KERNEL_RELEASE" >&2
  printf 'Igiris will use limited /proc polling until matching headers are installed and the service is restarted.\n' >&2
fi
if ! python3 -c 'import bcc' >/dev/null 2>&1; then
  printf 'Warning: BCC Python bindings are unavailable. Install python3-bpfcc for kernel-assisted collection.\n' >&2
fi
install -d -m 0755 /opt/igiris /etc/igiris
install -m 0644 "$ROOT/version.txt" /opt/igiris/version.txt
if systemctl is-active --quiet igiris; then
  printf 'Stopping running Igiris service before updating /opt/igiris.\n'
  systemctl stop igiris
fi
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
systemctl restart igiris
printf 'Igiris installed. Open http://127.0.0.1:8787 and enter your password.\n'
