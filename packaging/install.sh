#!/usr/bin/env bash
set -euo pipefail

confirm() {
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" == "yes" || "$reply" == "y" || "$reply" == "Y" ]]
}

detect_package_manager() {
  local manager
  for manager in apt-get dnf yum zypper pacman; do
    if command -v "$manager" >/dev/null 2>&1; then
      printf '%s\n' "$manager"
      return 0
    fi
  done
  return 1
}

# Populate DISTRO_* globals from /etc/os-release and board heuristics.
detect_environment() {
  OS_NAME="$(uname -s)"
  ARCHITECTURE="$(uname -m)"
  KERNEL_RELEASE="$(uname -r)"
  DISTRO_ID=""
  DISTRO_LIKE=""
  DISTRO_NAME=""
  DISTRO_VERSION=""
  IS_RASPBERRY_PI=false
  IS_DEBIAN_FAMILY=false
  IS_RHEL_FAMILY=false
  IS_SUSE_FAMILY=false
  IS_ARCH_FAMILY=false

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${NAME:-}"
    DISTRO_VERSION="${VERSION_ID:-}"
  fi

  if [[ -r /proc/device-tree/model ]] && grep -qi 'raspberry' /proc/device-tree/model 2>/dev/null; then
    IS_RASPBERRY_PI=true
  elif [[ -r /proc/cpuinfo ]] && grep -qi 'raspberry' /proc/cpuinfo 2>/dev/null; then
    IS_RASPBERRY_PI=true
  fi

  local id_blob
  id_blob="$(printf '%s %s' "$DISTRO_ID" "$DISTRO_LIKE" | tr '[:upper:]' '[:lower:]')"
  case " $id_blob " in
    *' debian '*|*' ubuntu '*|*' raspbian '*|*' kali '*|*' linuxmint '*|*' pop '*|*' neon '*)
      IS_DEBIAN_FAMILY=true
      ;;
  esac
  case " $id_blob " in
    *' rhel '*|*' fedora '*|*' centos '*|*' rocky '*|*' alma '*|*' amzn '*|*' ol '*)
      IS_RHEL_FAMILY=true
      ;;
  esac
  case " $id_blob " in
    *' suse '*|*' opensuse '*|*' sles '*)
      IS_SUSE_FAMILY=true
      ;;
  esac
  case " $id_blob " in
    *' arch '*|*' manjaro '*|*' endeavouros '*)
      IS_ARCH_FAMILY=true
      ;;
  esac

  # Raspberry Pi OS is Debian-based even when ID is raspbian/debian.
  if [[ "$IS_RASPBERRY_PI" == true ]]; then
    IS_DEBIAN_FAMILY=true
  fi
}

print_environment_summary() {
  printf 'Detected environment:\n'
  printf '  OS:            %s\n' "$OS_NAME"
  printf '  Architecture:  %s\n' "$ARCHITECTURE"
  printf '  Kernel:        %s\n' "$KERNEL_RELEASE"
  if [[ -n "$DISTRO_NAME" ]]; then
    printf '  Distribution:  %s' "$DISTRO_NAME"
    if [[ -n "$DISTRO_VERSION" ]]; then
      printf ' %s' "$DISTRO_VERSION"
    fi
    if [[ -n "$DISTRO_ID" ]]; then
      printf ' (%s)' "$DISTRO_ID"
    fi
    printf '\n'
  fi
  if [[ "$IS_RASPBERRY_PI" == true ]]; then
    printf '  Board:         Raspberry Pi\n'
  fi
  local family="unknown"
  if [[ "$IS_DEBIAN_FAMILY" == true ]]; then
    family="Debian/Ubuntu family"
  elif [[ "$IS_RHEL_FAMILY" == true ]]; then
    family="RHEL/Fedora family"
  elif [[ "$IS_SUSE_FAMILY" == true ]]; then
    family="SUSE family"
  elif [[ "$IS_ARCH_FAMILY" == true ]]; then
    family="Arch family"
  fi
  printf '  Family:        %s\n' "$family"
  if [[ -n "$PACKAGE_MANAGER" ]]; then
    printf '  Packages via:  %s\n' "$PACKAGE_MANAGER"
  else
    printf '  Packages via:  (none detected)\n'
  fi
}

packages_for_utility() {
  case "$PACKAGE_MANAGER:$1" in
    apt-get:npm) printf '%s\n' nodejs npm ;;
    dnf:npm|yum:npm|zypper:npm|pacman:npm) printf '%s\n' nodejs npm ;;
    apt-get:python3) printf '%s\n' python3 python3-venv python3-pip ;;
    dnf:python3|yum:python3) printf '%s\n' python3 python3-pip ;;
    zypper:python3) printf '%s\n' python3 python3-pip python3-virtualenv ;;
    pacman:python3) printf '%s\n' python python-pip ;;
    apt-get:systemctl) printf '%s\n' systemd ;;
    dnf:systemctl|yum:systemctl|zypper:systemctl|pacman:systemctl) printf '%s\n' systemd ;;
    apt-get:install|apt-get:cp|apt-get:rm|apt-get:chmod) printf '%s\n' coreutils ;;
    dnf:install|dnf:cp|dnf:rm|dnf:chmod) printf '%s\n' coreutils ;;
    yum:install|yum:cp|yum:rm|yum:chmod) printf '%s\n' coreutils ;;
    zypper:install|zypper:cp|zypper:rm|zypper:chmod) printf '%s\n' coreutils ;;
    pacman:install|pacman:cp|pacman:rm|pacman:chmod) printf '%s\n' coreutils ;;
  esac
}

install_packages() {
  case "$PACKAGE_MANAGER" in
    apt-get)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    dnf|yum) "$PACKAGE_MANAGER" install -y "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    pacman) pacman -Sy --needed --noconfirm "$@" ;;
  esac
}

ensure_utility() {
  local utility=$1 description=$2
  local -a packages=()
  command -v "$utility" >/dev/null 2>&1 && return 0

  mapfile -t packages < <(packages_for_utility "$utility")
  printf 'Required utility "%s" (%s) was not found.\n' "$utility" "$description" >&2
  if [[ -z "$PACKAGE_MANAGER" || ${#packages[@]} -eq 0 ]]; then
    printf 'Install it manually, then rerun this installer.\n' >&2
    exit 1
  fi
  if ! confirm "Do you wish to install the required package(s): ${packages[*]}?"; then
    printf 'Installation cancelled.\n'
    exit 1
  fi
  install_packages "${packages[@]}"
  if ! command -v "$utility" >/dev/null 2>&1; then
    printf 'Error: "%s" is still unavailable after package installation.\n' "$utility" >&2
    exit 1
  fi
}

# Return kernel config path content lines for BPF-related options (best-effort).
kernel_config_value() {
  local key=$1
  local config_file="/boot/config-${KERNEL_RELEASE}"
  if [[ -r "$config_file" ]]; then
    grep -E "^${key}=" "$config_file" 2>/dev/null | head -n1 || true
    return 0
  fi
  if [[ -r /proc/config.gz ]]; then
    zcat /proc/config.gz 2>/dev/null | grep -E "^${key}=" | head -n1 || true
    return 0
  fi
  printf ''
}

# Check whether a kernel config option is built-in (y) or modular (m).
kernel_config_enabled() {
  local key=$1
  local line
  line="$(kernel_config_value "$key")"
  [[ "$line" == "${key}=y" || "$line" == "${key}=m" ]]
}

has_kernel_headers() {
  [[ -e "/lib/modules/${KERNEL_RELEASE}/build" || -e /sys/kernel/kheaders.tar.xz ]]
}

has_bcc_python() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import bcc' >/dev/null 2>&1
}

# Kernel-side eBPF syscall support (compile-time config and/or runtime FS).
check_kernel_ebpf() {
  # Runtime evidence is preferred when present.
  if [[ -e /sys/fs/bpf || -e /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    return 0
  fi
  if kernel_config_enabled CONFIG_BPF_SYSCALL || kernel_config_enabled CONFIG_BPF; then
    return 0
  fi
  return 1
}

# BPF JIT: config and/or live sysctl.
check_bpf_jit() {
  local jit_sysctl="/proc/sys/net/core/bpf_jit_enable"
  if [[ -r "$jit_sysctl" ]]; then
    local value
    value="$(tr -d '[:space:]' <"$jit_sysctl" 2>/dev/null || true)"
    # 0 = disabled, 1 = enabled, 2 = enabled with traces
    if [[ "$value" == "1" || "$value" == "2" ]]; then
      return 0
    fi
    # Sysctl present but currently off — still count as available if kernel has JIT.
    if kernel_config_enabled CONFIG_BPF_JIT; then
      return 0
    fi
    return 1
  fi
  kernel_config_enabled CONFIG_BPF_JIT
}

report_ebpf_status() {
  local label=$1
  printf '%s\n' "$label"
  if check_kernel_ebpf; then
    printf '  Kernel eBPF:          available\n'
  else
    printf '  Kernel eBPF:          unavailable\n'
  fi
  if check_bpf_jit; then
    printf '  eBPF JIT:             available\n'
  else
    printf '  eBPF JIT:             unavailable\n'
  fi
  if has_kernel_headers; then
    printf '  Kernel headers:       available\n'
  else
    printf '  Kernel headers:       unavailable (need match for %s)\n' "$KERNEL_RELEASE"
  fi
  if has_bcc_python; then
    printf '  BCC Python bindings:  available\n'
  else
    printf '  BCC Python bindings:  unavailable\n'
  fi
  if [[ -r /sys/kernel/btf/vmlinux ]]; then
    printf '  BTF (vmlinux):        available\n'
  else
    printf '  BTF (vmlinux):        unavailable (optional for BCC)\n'
  fi
}

# Best-effort package list for BCC + headers + bpftool per distro family.
ebpf_packages_for_platform() {
  local -a packages=()

  case "$PACKAGE_MANAGER" in
    apt-get)
      packages+=(python3-bpfcc bpfcc-tools)
      # bpftool package name varies across Debian/Ubuntu releases.
      if apt-cache show bpftool >/dev/null 2>&1; then
        packages+=(bpftool)
      elif apt-cache show linux-tools-common >/dev/null 2>&1; then
        packages+=(linux-tools-common)
      fi
      if [[ "$IS_RASPBERRY_PI" == true ]]; then
        if apt-cache show raspberrypi-kernel-headers >/dev/null 2>&1; then
          packages+=(raspberrypi-kernel-headers)
        elif apt-cache show "linux-headers-${KERNEL_RELEASE}" >/dev/null 2>&1; then
          packages+=("linux-headers-${KERNEL_RELEASE}")
        fi
      elif apt-cache show "linux-headers-${KERNEL_RELEASE}" >/dev/null 2>&1; then
        packages+=("linux-headers-${KERNEL_RELEASE}")
      else
        # Metapackages for common Debian-family targets when exact headers are gone.
        case "$ARCHITECTURE" in
          aarch64|arm64)
            if apt-cache show linux-headers-arm64 >/dev/null 2>&1; then
              packages+=(linux-headers-arm64)
            elif apt-cache show linux-headers-generic >/dev/null 2>&1; then
              packages+=(linux-headers-generic)
            fi
            ;;
          x86_64|amd64)
            if apt-cache show linux-headers-amd64 >/dev/null 2>&1; then
              packages+=(linux-headers-amd64)
            elif apt-cache show linux-headers-generic >/dev/null 2>&1; then
              packages+=(linux-headers-generic)
            fi
            ;;
          armv7l|armhf)
            if apt-cache show linux-headers-armmp >/dev/null 2>&1; then
              packages+=(linux-headers-armmp)
            elif apt-cache show linux-headers-generic >/dev/null 2>&1; then
              packages+=(linux-headers-generic)
            fi
            ;;
          *)
            if apt-cache show linux-headers-generic >/dev/null 2>&1; then
              packages+=(linux-headers-generic)
            fi
            ;;
        esac
      fi
      ;;
    dnf|yum)
      packages+=(bcc bcc-tools python3-bcc kernel-devel bpftool)
      ;;
    zypper)
      packages+=(bcc-tools python3-bcc kernel-default-devel bpftool)
      ;;
    pacman)
      packages+=(bcc python-bcc linux-headers bpf)
      ;;
  esac

  if [[ ${#packages[@]} -gt 0 ]]; then
    printf '%s\n' "${packages[@]}"
  fi
}

# True when userland eBPF tooling required by Igris is fully present.
ebpf_userland_ready() {
  has_kernel_headers && has_bcc_python
}

# True when kernel + userland support full BCC mode.
ebpf_full_ready() {
  check_kernel_ebpf && ebpf_userland_ready
}

ensure_ebpf_support() {
  EBPF_AVAILABLE=false
  EBPF_JIT_AVAILABLE=false

  if [[ "$OS_NAME" != "Linux" ]]; then
    printf 'eBPF requires Linux; detected OS is %s. Igris will use /proc fallback mode.\n' "$OS_NAME" >&2
    return 0
  fi

  case "$ARCHITECTURE" in
    x86_64|amd64|aarch64|arm64|armv7l|armhf|ppc64le|s390x)
      ;;
    *)
      printf 'Architecture %s is not supported for eBPF by this installer.\n' "$ARCHITECTURE" >&2
      return 0
      ;;
  esac

  printf '\nChecking kernel eBPF support...\n'
  report_ebpf_status 'Pre-install eBPF status:'

  if ! check_kernel_ebpf; then
    printf 'Kernel eBPF support was not detected on this platform.\n' >&2
    printf 'Igris can still install and run in limited /proc polling mode.\n' >&2
    return 0
  fi

  if ebpf_full_ready; then
    EBPF_AVAILABLE=true
    if check_bpf_jit; then
      EBPF_JIT_AVAILABLE=true
    fi
    printf 'eBPF utilities are already available; Igris will work in full mode.\n'
    return 0
  fi

  # Kernel has eBPF but packages/headers/BCC are missing — offer install.
  local -a packages=()
  if [[ -n "$PACKAGE_MANAGER" ]]; then
    mapfile -t packages < <(ebpf_packages_for_platform)
  fi

  if [[ ${#packages[@]} -eq 0 ]]; then
    printf 'eBPF packages could not be determined for this platform.\n' >&2
    printf 'Install BCC Python bindings and matching kernel headers manually, then rerun.\n' >&2
    return 0
  fi

  printf 'eBPF userland packages are missing or incomplete for full mode.\n' >&2
  printf 'Recommended packages (%s): %s\n' "$PACKAGE_MANAGER" "${packages[*]}"
  if ! confirm 'Do you wish to install the eBPF packages now?'; then
    printf 'Skipping eBPF package installation.\n'
    return 0
  fi

  printf 'Installing eBPF packages...\n'
  if ! install_packages "${packages[@]}"; then
    printf 'Warning: eBPF package installation reported failures.\n' >&2
  fi

  printf '\nPost-installation eBPF verification...\n'
  report_ebpf_status 'Post-install eBPF status:'

  if check_kernel_ebpf; then
    printf 'Verified: kernel eBPF is available.\n'
  else
    printf 'Warning: kernel eBPF is still unavailable after package installation.\n' >&2
  fi

  if check_bpf_jit; then
    EBPF_JIT_AVAILABLE=true
    printf 'Verified: eBPF JIT is available.\n'
  else
    EBPF_JIT_AVAILABLE=false
    printf 'Warning: eBPF JIT is not available (programs may still load without JIT).\n' >&2
  fi

  if ebpf_full_ready; then
    EBPF_AVAILABLE=true
    printf 'eBPF utilities installed successfully; Igris will work in full mode.\n'
  else
    EBPF_AVAILABLE=false
    if ! has_kernel_headers; then
      printf 'Matching headers for running kernel %s are still unavailable.\n' "$KERNEL_RELEASE" >&2
      printf 'If packages installed a newer kernel/headers set, reboot into that kernel and rerun this installer.\n' >&2
    fi
    if ! has_bcc_python; then
      printf 'BCC Python bindings are still unavailable after package installation.\n' >&2
    fi
  fi
}

if [[ ${EUID} -ne 0 ]]; then echo "Run as root: sudo packaging/install.sh" >&2; exit 1; fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
detect_environment
PACKAGE_MANAGER="$(detect_package_manager || true)"
print_environment_summary

ensure_ebpf_support

if [[ "$EBPF_AVAILABLE" == true ]]; then
  if [[ "$EBPF_JIT_AVAILABLE" == true ]]; then
    printf 'eBPF and eBPF JIT are available; Igris will work in full mode.\n'
  else
    printf 'eBPF is available without JIT; Igris will work in full mode (no JIT acceleration).\n'
  fi
elif ! confirm 'eBPF is not fully available on this machine. Igris will continue in fallback /proc mode. Do you wish to continue to install?'; then
  printf 'Installation cancelled.\n'
  exit 1
fi

ensure_utility python3 'Python runtime and virtual environments'
ensure_utility npm 'frontend build tooling'
ensure_utility systemctl 'system service management'
ensure_utility install 'file installation'
ensure_utility cp 'file copying'
ensure_utility rm 'file replacement'
ensure_utility chmod 'file permissions'

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  printf 'Error: Python 3.11 or newer is required; found %s.\n' "$(python3 --version 2>&1)" >&2
  exit 1
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  VENV_PACKAGES=()
  case "$PACKAGE_MANAGER" in
    apt-get) VENV_PACKAGES=(python3-venv) ;;
    dnf|yum) VENV_PACKAGES=(python3) ;;
    zypper) VENV_PACKAGES=(python3-virtualenv) ;;
    pacman) VENV_PACKAGES=(python) ;;
  esac
  printf 'Required Python venv support was not found.\n' >&2
  if [[ ${#VENV_PACKAGES[@]} -eq 0 ]] || ! confirm "Do you wish to install the required package(s): ${VENV_PACKAGES[*]}?"; then
    printf 'Installation cancelled.\n'
    exit 1
  fi
  install_packages "${VENV_PACKAGES[@]}"
  if ! python3 -m venv --help >/dev/null 2>&1; then
    printf 'Error: Python venv support is still unavailable after package installation.\n' >&2
    exit 1
  fi
fi

printf 'Compiling the latest frontend bundle...\n'
npm --prefix "$ROOT/frontend" ci
npm --prefix "$ROOT/frontend" run build
rm -rf "$ROOT/src/igris/static"
install -d -m 0755 "$ROOT/src/igris/static"
cp -a "$ROOT/frontend/dist/." "$ROOT/src/igris/static/"
install -d -m 0755 /opt/igris /etc/igris
install -m 0644 "$ROOT/version.txt" /opt/igris/version.txt
if systemctl is-active --quiet igris; then
  printf 'Stopping running Igris service before updating /opt/igris.\n'
  systemctl stop igris
fi
PASSWORD_FILE=/etc/igris/password.verifier
python3 -m venv --system-site-packages /opt/igris/.venv
/opt/igris/.venv/bin/pip install "$ROOT"
if [[ ! -s "$PASSWORD_FILE" ]]; then
  printf 'Create the local Igris unlock password (minimum 12 characters).\n'
  /opt/igris/.venv/bin/igris-set-password --file "$PASSWORD_FILE"
else
  chmod 0600 "$PASSWORD_FILE"
  printf 'Existing Igris password verifier retained.\n'
fi
if [[ -e /etc/igris/igris.env ]]; then
  printf 'Existing Igris environment configuration retained.\n'
else
  install -m 0644 "$ROOT/packaging/igris.env" /etc/igris/igris.env
fi
install -m 0644 "$ROOT/packaging/igris.service" /etc/systemd/system/igris.service
systemctl daemon-reload
systemctl enable igris
systemctl restart igris
printf 'Igris installed. Check /etc/igris/igris.env for the active bind configuration.\n'
printf 'For authorized LAN access, set IGRIS_BIND_MODE=network, update IGRIS_ALLOWED_HOSTS, and restart the service.\n'
