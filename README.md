# Igiris - Blood-Red Commander

<p align="center">
  <img src="./assets/igiris_0xdhanesh.png" alt="Shadow-Army-Igiris" width="75%">
</p>

**Local-first Linux process and network evidence for defenders, incident responders, and authorized security testers.**

Igiris helps answer a deceptively difficult host-investigation question:

> Which process communicated, what executable launched it, what was loaded into that process, where did it connect, and what evidence supports the conclusion?

Linux exposes much of this information, but it is fragmented across process metadata, socket state, executable mappings, command lines, and short-lived kernel events. Igiris collects that evidence into a single investigation timeline without requiring a cloud telemetry service.

Igiris is an investigation and evidence tool. It does not automatically block traffic, declare a process malicious, or claim that every shared library mapped into a network-active process caused the connection.

## Who Igiris is for

### Blue Teams and incident responders

Use Igiris to:

- identify the exact process and executable associated with observed network activity;
- follow parent/child lineage from an application to a network-active helper process;
- review command lines, users, executable hashes, mapped libraries, and open files;
- investigate software launched from unusual writable locations;
- preserve recent process/network evidence for triage and incident reconstruction;
- compare activity against an analyst-defined baseline;
- export JSON or CSV evidence for case notes and downstream analysis.

Typical investigations include browser helper processes, unexpected background services, command-line download tools, suspicious child processes, and applications communicating with destinations not explained by normal use.

### Red Teams and authorized security testers

Use Igiris in systems you own or are explicitly authorized to assess to:

- validate whether test payloads produce expected process and network telemetry;
- understand which stage of a controlled execution chain initiates a connection;
- measure visibility gaps caused by process lifetime, privilege, or collection mode;
- compare operator activity with the evidence available to a defender;
- test detections for unusual executable paths, process lineage, and destination changes;
- document observable artifacts during adversary-emulation exercises.

Igiris is not intended for covert monitoring, unauthorized access, credential theft, or deployment outside an approved security scope.

## What Igiris records today

Igiris currently provides:

- process snapshots with PID, parent PID, root application, user, executable path, command line, and first/last-seen times;
- SHA-256 enrichment for readable executables;
- process trees grouped under an investigation root;
- live socket observations and retained connection history;
- remote address, port, protocol, address family, and available domain evidence;
- mapped shared-library paths from `/proc/<pid>/maps`;
- open-file paths from `/proc/<pid>/fd`;
- indicators for executables launched from writable or unusual paths;
- process-scoped and application-scoped timelines;
- search across process, artifact, hash, destination, and event fields;
- analyst baselines, evidence reset, retention, and JSON/CSV export;
- a password-protected local web interface with expiring in-memory sessions;
- automatic fallback to `/proc` polling when kernel event collection is unavailable.

Collection fidelity is always shown in the health response and interface. Running without the required privilege or kernel support reduces visibility rather than silently presenting partial data as complete.

## Evidence semantics

Igiris separates evidence types so analysts can judge what a record proves.

| Classification | Meaning |
|---|---|
| **Observed** | Directly captured from the kernel or a live Linux interface, such as a process, socket, syscall result, or mapped file. |
| **Correlated** | Two observations belonged to the same process generation or application lineage during an overlapping time window. |
| **Enriched** | Derived from observed data, such as a SHA-256 digest or parsed executable metadata. |
| **Heuristic** | A useful lead that is not proof, such as an executable residing under a commonly writable path. |

A library shown under a process means that it was mapped when Igiris inspected that process. It does **not** by itself prove that the library selected a destination or initiated a connection. Planned call-site attribution will narrow this relationship while retaining explicit confidence labels.

## Architecture

```text
Linux process/socket/kernel evidence
                │
                ▼
      Collector and enrichment
      ├─ process lineage
      ├─ executable hashing
      ├─ mapped images/open files
      ├─ socket and connect evidence
      └─ DNS/domain evidence when available
                │
                ▼
        SQLite evidence store
                │
                ▼
       FastAPI local API and UI
      ├─ investigation roots
      ├─ process timelines
      ├─ advanced evidence
      ├─ baseline and retention
      └─ JSON/CSV export
```

The backend is Python 3.11+, FastAPI, psutil, Pydantic, and SQLite. The interface is built with React and Vite. Linux-specific acquisition is kept behind collector boundaries so the evidence model can evolve independently.

## Collection modes

### `/proc` polling

The portable fallback inspects Linux process, mapping, file-descriptor, and socket state at a configurable interval. It supports useful host investigation without a native build chain, but a process or connection that starts and exits between observations can be missed.

### Kernel event collection

The current code can use an optional BCC path where supported. Kernel event collection requires elevated privilege and compatible kernel tooling. When it cannot initialize, Igiris reports reduced visibility and continues with polling.

A libbpf CO-RE collector is planned to replace runtime-compiled BCC as the primary event-driven path. See [Roadmap](#roadmap).

## Installation

### Requirements

- Linux;
- Python 3.11 or newer;
- root privileges for complete host telemetry and system service installation;
- Node.js/npm only when rebuilding the frontend;
- kernel BPF/BTF support for the planned native event collector.

### System installation

Review the installer and service policy before running them on a monitored host:

```bash
sudo bash packaging/install.sh
```

The installer:

- creates an isolated environment under `/opt/igiris`;
- prompts for a local unlock password with terminal echo disabled;
- stores only a salted scrypt verifier in `/etc/igiris/password.verifier` with owner-only permissions;
- installs the hardened systemd unit;
- binds the service to loopback by default;
- starts or restarts the service.

Check service health with:

```bash
sudo systemctl status igiris
sudo journalctl -u igiris -f
```

Open the interface using the address configured in `/etc/igiris/igiris.env`. The default configuration is local-only. If LAN access is enabled, add only the required hostnames or addresses to `IGIRIS_ALLOWED_HOSTS` and place TLS or an authenticated tunnel in front of Igiris.

### Change the unlock password

```bash
sudo /opt/igiris/.venv/bin/igiris-set-password \
  --file /etc/igiris/password.verifier
sudo systemctl restart igiris
```

The password is read interactively and is not placed in shell history. Restarting also invalidates every in-memory browser session.

## Development

Create an environment and install the backend:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Run backend tests:

```bash
.venv/bin/pytest -q
```

Install, test, and build the frontend:

```bash
cd frontend
npm ci
npm test
npm run build
```

Run the packaged application from the repository environment:

```bash
.venv/bin/igirisd
```

For collection testing, use only hosts, applications, and networks within your authorized scope.

## Investigation workflow

1. **Confirm visibility.** Check whether Igiris reports full kernel-assisted collection or limited polling.
2. **Select an application root.** Review its user, executable, activity counts, and destinations.
3. **Follow the process tree.** Identify the exact child process associated with the evidence.
4. **Inspect Advanced Mode.** Review invocation, executable digest, mapped libraries, open files, and process-scoped network events.
5. **Evaluate evidence strength.** Distinguish direct observations from correlation and heuristics.
6. **Set a baseline.** Keep the current evidence visible while focusing on strictly newer activity.
7. **Export or clear.** Export case evidence, or use the authenticated reset flow before a controlled test.

## API overview

The local API includes endpoints for:

- health and evidence revision;
- password login/logout;
- application roots and details;
- process-scoped events and advanced artifacts;
- baseline creation/removal;
- evidence reset;
- JSON and CSV export.

When the service is running, the OpenAPI description is available from the configured host at `/docs`. API requests require an active password session when authentication is configured.

## Security model

- **Local-first:** evidence is stored locally in SQLite and is not uploaded by Igiris.
- **Loopback by default:** the packaged service does not listen on the LAN unless explicitly reconfigured.
- **Host and Origin checks:** the API validates accepted host/origin values.
- **No plaintext password storage:** authentication uses a root-owned, owner-only salted scrypt verifier.
- **Bounded verification:** per-client throttling, bounded client state, and a global concurrency limit constrain expensive password checks.
- **Ephemeral sessions:** random bearer sessions exist only in process memory, expire automatically, and are revoked on logout or restart.
- **Least exposure:** the UI keeps its session in browser session storage rather than persistent local storage.
- **Service hardening:** the systemd unit applies filesystem and process restrictions while retaining the privilege required for host telemetry.

The collector observes sensitive host metadata, including command lines, file paths, users, and network destinations. Protect the database, exports, service account, and browser session as investigation evidence.

## Current limitations

- Polling can miss short-lived processes, mappings, and connections.
- PID-only historical identity can become ambiguous after PID reuse; generation-safe identity is planned.
- Browser DNS-over-HTTPS or DNS-over-TLS may expose only resolver/CDN connections rather than the original query name.
- PTR data and parsed command arguments are enrichment, not observed DNS requests, and must be labeled accordingly.
- Executable hashes can be unavailable when files are deleted, unreadable, or gone before enrichment.
- A mapped `.so` is correlated with a process, not automatically responsible for its network behavior.
- The current service does not capture packet contents, decrypt TLS, provide a fleet console, or enforce firewall policy.
- Linux is the only collector platform currently implemented.

## Roadmap

### Generation-safe process evidence

- identify a process by boot ID, TGID, kernel start time, and exec generation rather than PID alone;
- preserve every executable generation across same-PID `exec` transitions;
- retain parent/child identity without joining evidence across PID reuse.

### libbpf CO-RE event collector

- add a narrow privileged native helper using kernel BTF;
- capture process exec/exit and connect entry/exit events;
- capture executable `mmap`, `mprotect`, `mremap`, and `munmap` lifecycle events;
- record TGID and TID so network activity is attributed to the initiating thread;
- expose event-loss counters and explicit fallback reasons;
- keep the web/API process separate from the smallest practical privileged acquisition boundary.

### Defensible module and call-site attribution

- capture bounded user-space stacks at connection time where kernel policy permits;
- resolve instruction addresses against the process-generation mapping timeline;
- identify the syscall call-site module and supporting stack modules;
- distinguish the exact network-active process from its application root;
- present attribution as observed, correlated, or best-effort rather than asserting unsupported causation.

### Detection and evidence engineering

- ELF build IDs and stronger executable/image identity;
- signed or hash-chained exports for evidence-integrity workflows;
- configurable local detection rules and allowlists;
- Sigma-compatible or other interoperable event mappings where semantics align;
- richer retention controls and case-oriented export bundles;
- performance budgets and stress tests for high-process-count hosts.

### Broader deployment options

- tested packages for additional Linux distributions and architectures;
- optional remote collection through an authenticated, encrypted architecture;
- non-Linux acquisition backends only after their evidence semantics can remain explicit and comparable.

## Contributing

Security-sensitive changes should include:

- tests that fail before the fix and pass afterward;
- explicit evidence semantics;
- no committed credentials or private investigation data;
- static analysis and dependency-audit results;
- documentation of privilege, performance, and fallback behavior.

Before opening a change, run:

```bash
.venv/bin/pytest -q
cd frontend && npm test && npm run build && npm audit --audit-level=high
```

## Responsible use

Use Igiris only on systems and networks you own or have explicit permission to monitor or assess. Follow applicable law, organizational policy, data-retention requirements, and rules of engagement.
