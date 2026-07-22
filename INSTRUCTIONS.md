# eBPF availability and recovery on Kali ARM64

Igiris uses BCC to compile and load an eBPF program at runtime. If any BCC
prerequisite is unavailable, Igiris deliberately falls back to `/proc` polling.
The fallback remains useful, but it can miss processes and connections that
start and finish between polling intervals.

These instructions assume a Kali ARM64 system (`uname -m` reports `aarch64`).
Run commands from the Igiris repository unless a command says otherwise.

## 1. Check the running kernel and architecture

```bash
uname -m
uname -r
```

Do not compare only the major kernel version. The installed headers must match
the complete string printed by `uname -r`, including the `+kali-arm64` suffix.

## 2. Check kernel eBPF support

The most useful checks are:

```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF: available" || echo "BTF: unavailable"
mountpoint /sys/fs/bpf
sudo bpftool feature probe kernel
```

`bpftool feature probe kernel` must run as root to report all privileged kernel
features accurately. Look for supported BPF syscall, program types, map types,
and tracing helpers. `/sys/kernel/btf/vmlinux` confirms that the running kernel
publishes BTF metadata; it does not, by itself, prove that BCC can compile and
load Igiris's program.

If `bpftool` is not installed, install it with:

```bash
sudo apt-get update
sudo apt-get install bpftool
```

For a config-level check, use the running kernel's config when available:

```bash
grep -E '^CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|BPF_EVENTS|KPROBES|KPROBE_EVENTS|TRACEPOINTS)=' \
  "/boot/config-$(uname -r)"
```

At minimum, Igiris's BCC path needs BPF syscall support and tracing facilities.
Kali's standard ARM64 kernel normally enables these options.

## 3. Check the BCC runtime prerequisites used by Igiris

Igiris requires all three of the following:

1. The service runs as root.
2. the `bcc` Python module is importable;
3. matching kernel headers are exposed through
   `/lib/modules/$(uname -r)/build`, or the in-kernel headers interface exists at
   `/sys/kernel/kheaders.tar.xz`.

Check them directly:

```bash
test "$(id -u)" -eq 0 && echo "Privilege: root" || echo "Privilege: not root"
python3 -c 'import bcc; print("BCC Python bindings: available")'
test -e "/lib/modules/$(uname -r)/build" \
  && readlink -f "/lib/modules/$(uname -r)/build" \
  || echo "Matching build headers: unavailable"
test -e /sys/kernel/kheaders.tar.xz \
  && echo "In-kernel headers: available" \
  || echo "In-kernel headers: unavailable"
```

The service privilege can be checked independently of the current shell:

```bash
sudo systemctl show igiris -p User -p Group -p DynamicUser
sudo systemctl status igiris --no-pager
```

The packaged service is expected to run as root because loading eBPF programs
and observing system-wide process/network events require privilege.

## 4. Fix missing dependencies on Kali ARM64

Refresh package metadata and install BCC, its tools, the ARM64 kernel-header
metapackage, and `bpftool`:

```bash
sudo apt-get update
sudo apt-get install python3-bpfcc bpfcc-tools linux-headers-arm64 bpftool
```

Use `linux-headers-arm64`, not a guessed, hard-coded kernel version. The
metapackage installs the kernel/header version currently offered by the
configured Kali repositories.

Confirm what was installed:

```bash
dpkg-query -W linux-image-arm64 linux-headers-arm64 python3-bpfcc bpfcc-tools bpftool
ls -ld /lib/modules/*/build
```

### When the running kernel is older than the available headers

A common Kali rolling-release failure looks like this:

```text
/lib/modules/<running-kernel>/build: No such file or directory
```

This means BCC cannot compile against the running kernel. It does **not** mean
that eBPF is disabled. If the repository no longer carries headers for the
running kernel, installing `linux-headers-arm64` installs a newer matching
kernel and header set. Reboot into that kernel:

```bash
sudo reboot
```

After reconnecting, verify that the running release and build link agree:

```bash
uname -r
readlink -f "/lib/modules/$(uname -r)/build"
test -e "/lib/modules/$(uname -r)/build" && echo "Matching headers: available"
```

If the link is still absent, inspect installed and repository versions before
changing anything else:

```bash
dpkg -l 'linux-image*arm64*' 'linux-headers*arm64*'
apt-cache policy linux-image-arm64 linux-headers-arm64
```

The image and headers selected for boot must have the same full release. Do not
symlink headers from a different kernel version into `/lib/modules`; generated
headers and kernel ABI details must match the running kernel.

## 5. Reinstall and restart Igiris

After booting the kernel with matching headers:

```bash
cd /home/kali/Desktop/Igiris
sudo bash packaging/install.sh
sudo systemctl restart igiris
sudo journalctl -u igiris -n 100 --no-pager
```

The installer creates a virtual environment with `--system-site-packages`, which
allows it to import Kali's `python3-bpfcc` module. If Igiris was installed by a
different method, verify the exact service interpreter instead of assuming that
a successful system Python import is sufficient:

```bash
sudo /opt/igiris/.venv/bin/python -c 'import bcc; print(bcc.__file__)'
```

Never put a sudo password in this file, a command line, shell history, a service
unit, or an environment file. Enter it only at sudo's interactive prompt.

## 6. Confirm that Igiris is using eBPF

Open the Igiris interface and check collection health. Full collection reports
mode `ebpf+bcc`, visibility `full`, and `ebpf_available: true`. The status
message should say that kernel-assisted connect-syscall and exec capture is
active.

Also inspect the journal for BCC compiler, verifier, permission, or tracepoint
errors:

```bash
sudo journalctl -u igiris -b --no-pager
```

Generate a harmless local test event only on a host you are authorized to
monitor, then confirm it appears in Igiris:

```bash
curl -I http://127.0.0.1:8787/
```

If the UI still reports limited `/proc` polling, re-run the checks in sections
2 and 3 under the service's runtime conditions. The reported message identifies
whether the remaining issue is service privilege, missing Python bindings,
missing matching headers, or a BCC load/compile failure.

## Current verified Kali ARM64 example

On the machine used to validate these instructions, the working state was:

```text
architecture:             aarch64
running kernel:           7.0.12+kali-arm64
linux-headers-arm64:      7.0.12-2kali1
python3-bpfcc/bpfcc-tools 0.35.0+ds-1.1
/sys/kernel/btf/vmlinux:  present
/sys/fs/bpf:              mounted
matching build link:      /lib/modules/7.0.12+kali-arm64/build
```

The earlier failure occurred on `6.19.14+kali-arm64` because its matching build
directory was absent. Installing `linux-headers-arm64` and rebooting selected
the newer kernel with matching headers, resolving the BCC initialization error.
