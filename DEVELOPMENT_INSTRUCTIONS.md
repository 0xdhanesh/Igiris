# Igris development instructions

This document is the working guide for human contributors and AI agents. It describes the repository contract, development setup, architecture, verification commands, deployment flow, and the conditions for calling a task complete.

## Project scope

Igris is a local-first Linux process and network investigation tool. It collects process lineage, executable metadata, network events, and advanced artifacts into SQLite, exposes them through a FastAPI API, and renders a React/Vite investigation UI. Use it only on systems and networks you own or are explicitly authorized to monitor.

## Repository layout

```text
src/igiris/             Python package and runtime application
  api.py                FastAPI routes, auth middleware, static-file serving
  main.py               application lifecycle and collector selection
  collectors.py         /proc polling collector and enrichment helpers
  ebpf.py               BCC program and kernel event collector
  processes.py          process snapshots, lineage, hashes, /proc artifacts
  models.py             Pydantic evidence models
  store.py              SQLite schema and persistence operations
  auth.py/auth_cli.py   password verifier and session authentication
  static/               compiled frontend served by the installed application
frontend/src/           React/Vite source, tests, and CSS
frontend/dist/          generated frontend output (ignored by Git)
tests/                  Python tests and local workflow helper scripts
packaging/              installer, reinstall helper, service unit, environment
.github/workflows/      CI, security, CodeQL, and release definitions
version.txt             single release-version source of truth
assets/                 project artwork and documentation assets
```

`src/igiris/static` must exactly match `frontend/dist` before packaging. Never hand-edit generated assets. The installer rebuilds the frontend and synchronizes those directories.

## Development environment

Requirements: Linux, Python 3.11 or newer, Node.js/npm for frontend work, and Git. Root privileges and BCC/kernel headers are required only for full live eBPF collection, not for ordinary unit tests.

```bash
cd /home/kali/Desktop/Igris
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cd frontend
npm ci
cd ..
```

The repository Python environment is for development. The production installer creates a separate `/opt/igiris/.venv` and does not reuse `.venv`.

## Running locally

Run the backend from the repository environment:

```bash
.venv/bin/igirisd
```

The default development settings come from `src/igiris/config.py` and environment variables prefixed with `IGIRIS_`. Do not commit passwords, database files, tokens, or local `.env` files. For a frontend-only development server:

```bash
cd frontend
npm run dev
```

The browser UI is normally served by FastAPI from `src/igiris/static` after a production build.

## Versioning

Edit `version.txt` when changing the application version. Use a plain value such as `0.2.0`; the UI displays it as `v0.2.0`. The installer copies it to `/opt/igiris/version.txt`, the backend exposes it in `/api/health`, and the frontend displays the backend-reported value. Keep frontend and backend changes in one commit and rebuild the frontend before packaging.

## Architecture and implementation rules

Evidence flows from a collector to enrichment code, then to `Store`, API responses, and the UI:

```text
Linux /proc and kernel events -> collector -> models -> SQLite Store -> FastAPI -> React UI
```

- Keep acquisition logic in `collectors.py`, `ebpf.py`, or `processes.py`; do not put `/proc` or BCC logic in API routes.
- Persist typed `Event`, `ProcessNode`, and `ProcessArtifact` models rather than ad-hoc dictionaries.
- Preserve evidence semantics. Distinguish observed, correlated, enriched, and heuristic information; do not present correlation as causation.
- Preserve the explicit limited/full visibility status. Fallback behavior must remain visible to users.
- Keep API authentication, host/origin checks, cache-control, and export escaping intact.
- Treat PID reuse, process lifetime, permissions, and missing kernel support as real collection conditions.
- When changing response shapes, update both backend tests and the React consumers.
- Do not silently discard evidence to make a UI look cleaner; filter only at a documented presentation boundary.
- Do not commit generated `frontend/node_modules` or `frontend/dist` output. The packaged `src/igiris/static` tree is synchronized by the build/install process.

## Testing and local CI

Run the same practical checks as GitHub CI before pushing:

```bash
./tests/python.sh       # pytest, compileall, pip check
./tests/frontend.sh     # npm ci, frontend tests/build, static diff
./tests/package.sh      # installer syntax and wheel inspection
./tests/all.sh          # Python, frontend, and package checks
./tests/security.sh     # gitleaks, Semgrep, Bandit, pip-audit, npm audit, zizmor
```

The security script requires the corresponding tools and network access. Individual workflow equivalents are:

```bash
python -m pytest -q
python -m compileall -q src
python -m pip check
(cd frontend && npm ci && npm test && npm run build)
diff -qr frontend/dist src/igiris/static
bash -n packaging/install.sh packaging/reinstall.sh
```

If a local environment has incompatible pytest warning plugins, use the project-supported Python environment and diagnose the environment rather than weakening tests or deleting warning configuration.

## Frontend build and deployment

The production service uses `/opt/igiris`. To deploy the current repository while retaining that location:

```bash
sudo bash packaging/reinstall.sh
sudo systemctl status igiris
sudo journalctl -u igiris -n 100 --no-pager
```

`packaging/install.sh` compiles the frontend, synchronizes `frontend/dist` to `src/igiris/static`, copies `version.txt`, installs the package into `/opt/igiris`, installs the systemd unit/environment, and restarts the service. It requires npm. The service must run as root for system-wide BCC collection.

After deployment, verify `/api/health`: full collection should report `mode: ebpf+bcc`, `visibility: full`, and `ebpf_available: true`. If it reports `proc-polling`, inspect the journal for privilege, BCC, headers, tracepoint, or compiler errors.

## GitHub workflows

- `ci.yml`: Python 3.11/3.12/3.13 tests, compileall, pip check, frontend tests/build/static comparison, package build and wheel inspection.
- `security.yml`: Gitleaks, Semgrep, Bandit, Python and npm dependency audits, and zizmor workflow auditing.
- `codeql.yml`: Python and JavaScript/TypeScript CodeQL analysis.
- `release.yml`: frontend verification, Python tests, distributions, SPDX SBOM, checksums, and release publication for `v*.*.*` tags.

Before pushing, run `./tests/all.sh`, `./tests/security.sh`, inspect `git diff --check`, and confirm `git status` contains only intended files. Do not bypass a failing required job by changing a test expectation without understanding the behavior under test.

## Safe change workflow for humans and AI agents

1. Read this file, the relevant source, tests, and workflow before editing.
2. Locate the narrowest owner of the behavior; avoid unrelated refactors.
3. State assumptions when a change affects evidence semantics, security, deployment, or generated assets.
4. Implement the smallest complete change with `apply_patch` or an equivalent reviewable edit.
5. Add or update regression tests for changed behavior, including fallback/error paths where applicable.
6. Rebuild generated frontend/package artifacts through the documented command, never by hand.
7. Run focused tests first, then the applicable scripts in `tests/`.
8. Review the diff, secrets, permissions, version, and generated-file synchronization.
9. Report what changed, what passed, and any environment-limited checks honestly.

Do not run destructive commands against the repository, database, `/opt/igiris`, or system service unless the task explicitly authorizes it. Keep secrets out of logs and commits. For security-sensitive changes, run the security checks and explain any accepted finding.

## Definition of done

A task is complete only when all applicable conditions are true:

- The requested behavior is implemented in the correct layer.
- Existing behavior and security boundaries remain intact.
- Regression tests cover the new behavior and pass.
- Python sources compile, dependencies pass `pip check`, and frontend output builds.
- `frontend/dist` and `src/igiris/static` are identical when frontend code changed.
- Packaging scripts pass `bash -n` and the wheel can be installed/imported when packaging changed.
- Version changes use `version.txt` and are visible through backend health/UI after rebuild.
- Relevant CI/security scripts pass, or any blocked check is explicitly documented with its cause.
- `git diff --check` is clean and no unintended generated files, secrets, databases, or caches are included.
- The final handoff names changed files, verification performed, deployment implications, and any remaining limitation.

## Troubleshooting quick reference

`proc-polling` means the BCC collector was unavailable or failed initialization. Check:

```bash
sudo journalctl -u igiris -n 100 --no-pager
sudo /opt/igiris/.venv/bin/python -c 'import bcc; print(bcc.__file__)'
uname -r
readlink -f "/lib/modules/$(uname -r)/build"
```

If the UI does not reflect a frontend change, rebuild and synchronize the static bundle, then reinstall/restart. If a workflow fails, reproduce its exact command locally before changing code or workflow policy.
