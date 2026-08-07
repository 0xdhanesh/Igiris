# Igris -  Blood-Red Commander

<p align="center">
  <img src="./assets/igris_0xdhanesh.png" alt="Igris investigation monitor" width="75%">
</p>

> **One-line:** Local-first Linux process + network investigation monitor. Collects evidence on-host, stores it in SQLite, serves a password-protected web UI and API. No cloud required.

| Data | Data - Extended :P |
|---|---|
| **Version** | 1.2.0 (`version.txt`) |
| **Platform** | Linux (collector); Python 3.11+ |
| **Stack** | FastAPI · uvicorn · psutil · Pydantic · SQLite · React/Vite · optional BCC/eBPF |
| **Entry points** | `igrisd` (daemon) · `igris-set-password` · `packaging/install.sh` |
| **Default UI** | `http://127.0.0.1:8787` (loopback only) |
| **Not** | Firewall, EDR, SIEM, packet capture, malware verdict engine |

**Core question this project answers**

> Which process communicated, what launched it, what was loaded into it, where did it connect, and what evidence supports that?

---

## For AI assistants (and busy humans)

If you are summarizing or navigating this repository, start here.

### What this project is

Igris is an **investigation and evidence** tool for a single Linux host. It watches processes and network activity, groups them under application roots, and presents a timeline in a local web app. It **does not** block traffic, decrypt TLS, or auto-label malware.

### Important features (highlight these)

| Feature | What it does |
|---|---|
| Process snapshots | PID, PPID, user, exe path, cmdline, first/last seen |
| Investigation roots | Walk parents until systemd/init/sshd/desktop shells; group evidence under a root |
| Live + historical network | Current sockets and retained connect transitions |
| Domain context | DNS tool queries, curl/wget/ping host args; optional PTR |
| Executable hashing | SHA-256 of readable binaries |
| Libraries & open files | From `/proc` maps/fds, or eBPF open events in full mode |
| Call-site stacks (v1.2) | User-space stacks on `connect`/`execve` via BCC when eBPF is available |
| Odd-path heuristics | Flag exes under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user` |
| Dual collection modes | Full: eBPF+BCC · Fallback: `/proc` polling (status always shown) |
| Local auth | scrypt password verifier; in-memory Bearer sessions |
| Evidence store | SQLite WAL, retention hours, soft disk cap |
| Export | JSON + CSV |
| Baseline | Mark “now” and focus on activity after |
| Hardened package install | systemd unit, localhost bind default, installer eBPF package prompts |

### How data flows

```text
Linux /proc + sockets (+ optional BCC eBPF)
        → Collector (PollingCollector | BccCollector)
        → Models (Event, ProcessNode, ProcessArtifact)
        → Store (SQLite)
        → FastAPI (/api/* + static React UI)
```

### Repository map (what lives where)

```text
Igris/
├── src/igris/           # Python package = the application
│   ├── main.py           # Startup, collector choice, uvicorn
│   ├── config.py         # IGRIS_* settings
│   ├── collectors.py     # /proc polling + enrichment
│   ├── ebpf.py           # BCC eBPF program + stack resolution
│   ├── processes.py      # Snapshots, roots, hashes, maps/fds
│   ├── models.py         # Evidence types
│   ├── store.py          # SQLite schema + queries
│   ├── api.py            # Routes, auth middleware, SPA
│   ├── auth.py           # scrypt + sessions
│   ├── auth_cli.py       # igris-set-password
│   └── static/           # Built UI (from frontend/dist)
├── frontend/             # React/Vite source + node tests
│   └── src/              # UI modules (auth, dashboard, timeline, …)
├── packaging/            # install.sh, systemd unit, igris.env
├── tests/                # pytest + shell CI helpers
├── assets/               # Artwork for docs
├── version.txt           # Release version source of truth
├── INSTRUCTIONS.md       # eBPF recovery (e.g. Kali ARM64)
├── DEVELOPMENT_INSTRUCTIONS.md
└── SECURITY_SCANNING.md
```

### Key files to open first

| Goal | Open |
|---|---|
| App lifecycle | `src/igris/main.py` |
| HTTP API surface | `src/igris/api.py` |
| Settings / env vars | `src/igris/config.py` · `packaging/igris.env` |
| Polling collector | `src/igris/collectors.py` |
| eBPF collector | `src/igris/ebpf.py` |
| DB schema | `src/igris/store.py` |
| Production install | `packaging/install.sh` · `packaging/igris.service` |
| UI entry | `frontend/src/main.jsx` |

### Quick commands

```bash
# Install on a Linux host (review script first)
sudo bash packaging/install.sh

# Dev backend
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/igrisd

# Tests
.venv/bin/pytest -q
cd frontend && npm ci && npm test && npm run build
tests/all.sh
```

---

## Who uses it

| Audience | Typical use |
|---|---|
| **Blue team / IR** | Attribute connections to process + exe; lineage; exports for cases |
| **Red team / authorized testers** | Validate payload telemetry; measure visibility gaps |
| **Reverse engineers / malware analysts** | Libraries, open files, eBPF call-site stacks on connect |
| **Not for** | Covert unauthorized monitoring; fleet SIEM; automated blocking |

**Responsible use:** only on systems/networks you own or are explicitly authorized to monitor.

---

## Architecture (backend)

### Runtime components

| Component | Responsibility |
|---|---|
| **`igrisd`** | Loads settings, opens DB, starts collector task, serves FastAPI |
| **Collector** | Continuously gathers host evidence |
| **Store** | Persists processes, events, artifacts; retention/cleanup |
| **API + auth** | Password login, Bearer sessions, investigation endpoints |
| **Static UI** | Built React app served from the same process |

### Collector selection (`main.py`)

1. Check BCC readiness: **root**, importable `bcc`, matching kernel headers (`/lib/modules/$(uname -r)/build` or kheaders).
2. If ready → `BccCollector` (eBPF + still enriches via `/proc`).
3. Else → `PollingCollector` only.
4. If eBPF init fails at runtime → automatic fall back to polling; status messages updated.

**Health signals:** `/api/health` reports `mode` (`ebpf+bcc` | `proc-polling`), `visibility` (`full` | `limited`), `ebpf_available`, and diagnostic `messages`. Never treat limited mode as complete coverage.

### Collection modes

| Mode | Requirements | Captures well | Misses |
|---|---|---|---|
| **eBPF + BCC** | root, BCC, matching headers, kernel BPF | Short-lived connect/exec/open; user stacks | Needs packages; may need reboot after newer headers |
| **`/proc` polling** | Linux + privilege for broad visibility | Steady-state processes and sockets | Activity between poll intervals |

Installer (`packaging/install.sh`) detects distro/board, probes eBPF/JIT, can prompt to install packages (`apt`/`dnf`/`yum`/`zypper`/`pacman`), then re-verifies. Deep Kali/ARM recovery: [`INSTRUCTIONS.md`](./INSTRUCTIONS.md).

### Evidence types (`models.py`)

| Type | Meaning |
|---|---|
| **Observed** | Direct from kernel or live `/proc`/socket interfaces |
| **Correlated** | Same process/lineage in an overlapping window |
| **Enriched** | Derived (hash, tool-arg hostname, optional PTR) |
| **Heuristic** | Lead only (e.g. odd writable path) |

Mapped libraries ≠ proven connect call-site. Stack frames in `raw_meta` (eBPF mode) strengthen attribution but still need human judgment.

### SQLite tables (`store.py`)

- `processes` — nodes by PID  
- `events` — connect, dns, icmp, exec_network_tool, live_socket  
- `process_artifacts` — library/file paths + source  
- `preferences` — baseline timestamp, etc.  

DB parent dir mode `0700`, files `0600`.

### API surface (`api.py`)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Password → Bearer token |
| `POST` | `/api/auth/logout` | Revoke session |
| `GET` | `/api/health` | Version + collector status |
| `GET` | `/api/revision` | UI change detection |
| `GET` | `/api/parents` | Application roots |
| `GET` | `/api/parents/{root_pid}` | Tree + events for a root |
| `GET` | `/api/events` | Filtered event list |
| `GET` | `/api/parents/{root_pid}/processes/{pid}/advanced` | Libraries, files, stacks, network |
| `POST`/`DELETE` | `/api/baseline` | Set/clear baseline |
| `DELETE` | `/api/evidence` | Clear store + collector tracking |
| `GET` | `/api/export.json` · `/api/export.csv` | Export |

Interactive docs: `/docs` when running. Auth required for API when a password verifier is configured.

### Frontend (`frontend/`)

React + Vite. Modules: auth, dashboard, timeline, revision polling, refresh highlights. Production build lands in `src/igris/static` (installer rebuilds and syncs; do not hand-edit generated assets).

---

## Get it working

### Requirements

- Linux host for real collection  
- Python **3.11+**  
- **Root** for system install and full telemetry  
- Node/npm only to rebuild the UI  
- Full mode: BCC packages + matching **kernel headers**  

### Production install

```bash
# Read packaging/install.sh first
sudo bash packaging/install.sh
sudo systemctl status igris
curl --noproxy '*' http://127.0.0.1:8787/api/health
```

What the installer does:

1. Detect environment (OS, arch, distro, Raspberry Pi, package manager)  
2. Check eBPF / JIT / headers / BCC; optionally install packages  
3. `npm ci` + build frontend → copy into package static  
4. Install under `/opt/igris` with venv (`--system-site-packages` for distro BCC)  
5. Create unlock password → `/etc/igris/password.verifier`  
6. Install `/etc/igris/igris.env` + systemd unit; enable & restart  

Config file: `/etc/igris/igris.env`  
Logs: `sudo journalctl -u igris -f`  
Password change:

```bash
sudo /opt/igris/.venv/bin/igris-set-password --file /etc/igris/password.verifier
sudo systemctl restart igris
```

### Development run

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cd frontend && npm ci && npm run build && cd ..
.venv/bin/igrisd
```

Dev DB default: `~/.local/share/igris/igris.db` (override with `IGRIS_DATABASE_PATH`). Full eBPF collection still needs root + BCC on Linux.

### Investigation workflow (operator)

1. Confirm health visibility (full vs limited)  
2. Pick an application root  
3. Walk the process tree to the network-active PID  
4. Open Advanced Mode (hash, libraries, files, stacks, events)  
5. Judge observed vs correlated vs heuristic  
6. Set baseline / export JSON or CSV / clear evidence for a clean test  

---

## Configuration (`IGRIS_*`)

All settings: `src/igris/config.py`. Packaged defaults: `packaging/igris.env`.

### Bind and access

| Variable | Default | Notes |
|---|---|---|
| `IGRIS_BIND_MODE` | `localhost` | `localhost`→`127.0.0.1`, `network`→`0.0.0.0` |
| `IGRIS_BIND_HOST` | unset | If set, overrides mode (legacy) |
| `IGRIS_BIND_PORT` | `8787` | Listen port |
| `IGRIS_ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` | Host + Origin allow list |

Prefer localhost; use `network` only on authorized LANs with firewall + tight `ALLOWED_HOSTS`. Restart after changes: `sudo systemctl restart igris`.

### Auth

| Variable | Default | Notes |
|---|---|---|
| `IGRIS_PASSWORD_VERIFIER_FILE` | `/etc/igris/password.verifier` | scrypt verifier path |
| `IGRIS_SESSION_TTL_SECONDS` | `28800` | 8h sessions |
| `IGRIS_LOGIN_MAX_FAILURES` | `5` | Per-client throttle |
| `IGRIS_LOGIN_FAILURE_WINDOW_SECONDS` | `60` | Throttle window |
| `IGRIS_LOGIN_MAX_PARALLEL_CHECKS` | `2` | Cap concurrent scrypt |

### Collection and storage

| Variable | Default | Notes |
|---|---|---|
| `IGRIS_DATABASE_PATH` | package: `/var/lib/igris/igris.db` | SQLite file |
| `IGRIS_RETENTION_HOURS` | `24` | History window |
| `IGRIS_SOFT_DISK_CAP_MB` | `512` | Soft size budget |
| `IGRIS_POLL_INTERVAL` | `1.0` | Main poll seconds |
| `IGRIS_EXEC_POLL_INTERVAL` | `0.2` | Faster network-tool poll |
| `IGRIS_COLLECTOR_ENABLED` | `true` | API-only if false |
| `IGRIS_PTR_FALLBACK` | `false` | Reverse DNS enrichment |
| `IGRIS_NETWORK_TOOLS` | `curl,wget,ping,...` | Tool name set |

### Minimal secure env example

```ini
IGRIS_BIND_MODE=localhost
IGRIS_BIND_PORT=8787
IGRIS_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]
IGRIS_PASSWORD_VERIFIER_FILE=/etc/igris/password.verifier
IGRIS_DATABASE_PATH=/var/lib/igris/igris.db
IGRIS_RETENTION_HOURS=24
```

---

## Security model (short)

- Evidence stays on the host (no Igris cloud upload)  
- Loopback bind by default  
- TrustedHost + Origin checks  
- scrypt verifier only (no plaintext password storage)  
- Bounded login failures and parallel password checks  
- Ephemeral in-memory sessions; UI uses sessionStorage  
- systemd hardening (`ProtectSystem`, `PrivateTmp`, …); service still **root** for host-wide collection  

Protect the DB, exports, verifier file, and browser session like case material.

---

## Development and tests

```bash
.venv/bin/pytest -q
cd frontend && npm test && npm run build
tests/python.sh && tests/frontend.sh && tests/package.sh
# optional: tests/security.sh
```

Contributor contract: [`DEVELOPMENT_INSTRUCTIONS.md`](./DEVELOPMENT_INSTRUCTIONS.md).  
Security scanning notes: [`SECURITY_SCANNING.md`](./SECURITY_SCANNING.md).

CI lives under `.github/workflows/` (ci, security, CodeQL, release).

---

## Limitations

- Polling misses short-lived activity between intervals  
- PID reuse can confuse history (generation-safe IDs planned)  
- Browser DoH/DoT may hide original names  
- No packet contents, TLS decrypt, fleet console, or blocking  
- Linux collectors only today  

## Roadmap (high level)

- Generation-safe process identity  
- libbpf CO-RE collector (replace runtime BCC as primary path)  
- Stronger call-site attribution and evidence packaging  
- Broader distro/arch packaging  

## License / contribution expectations

Security-sensitive PRs need failing-then-passing tests, clear evidence semantics, no secrets/case data, and docs for privilege and fallbacks. See the PR template under `.github/`.
