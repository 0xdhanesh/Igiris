# AGENTS.md — AI agent instructions for Igris

This file is the **entry point for AI coding agents** working on Igris.
Read it fully before editing code. For environment setup, tests, packaging,
and definition of done, also follow [`DEVELOPMENT_INSTRUCTIONS.md`](./DEVELOPMENT_INSTRUCTIONS.md).
Project overview lives in [`README.md`](./README.md). eBPF recovery is in
[`INSTRUCTIONS.md`](./INSTRUCTIONS.md).

Work on the **`dev`** branch unless the user names another branch.

---

## What Igris is

Igris is a **local-first Linux process + network investigation monitor**.
It collects process lineage, executable metadata, network events, and
artifacts into **SQLite**, exposes them through **FastAPI**, and renders a
**React/Vite** UI. No cloud. No blocking. No automatic malware verdicts.

Core question the product answers:

> Which process communicated, what launched it, what was loaded into it,
> where did it connect, and what evidence supports that?

Use only on systems and networks the operator owns or is authorized to monitor.

---

## Stack and layout (do not invent new homes)

| Area | Location |
|------|----------|
| Backend package | `src/igris/` |
| API routes / auth middleware | `src/igris/api.py` |
| App lifecycle / collector choice | `src/igris/main.py` |
| `/proc` polling + enrichment | `src/igris/collectors.py` |
| BCC eBPF collector | `src/igris/ebpf.py` |
| Process snapshots, roots, hashes | `src/igris/processes.py` |
| Pydantic models | `src/igris/models.py` |
| SQLite schema + queries | `src/igris/store.py` |
| Settings (`IGRIS_*`) | `src/igris/config.py` |
| Frontend source | `frontend/src/` |
| Packaged static UI | `src/igris/static/` (must match `frontend/dist`) |
| Tests | `tests/`, `frontend/src/*.test.js` |
| Installer / systemd | `packaging/` |
| Version source of truth | `version.txt` |

**Evidence pipeline (keep layers strict):**

```text
Linux /proc + kernel events
  → collector (collectors.py | ebpf.py)
  → models (Event, ProcessNode, ProcessArtifact, …)
  → Store (SQLite)
  → FastAPI
  → React UI
```

- Do **not** put `/proc` or BCC logic in API routes.
- Do **not** persist ad-hoc dicts when a model exists.
- Preserve evidence semantics: **observed** vs **correlated** vs **enriched** vs **heuristic**.
- Never present correlation as causation.
- Collection mode / visibility (`full` vs `limited`) must stay explicit to the user.

---

## Current baseline behavior (important context)

Baseline **already exists** as a **timestamp** preference (`preferences.baseline_ts`):

- API: `POST/DELETE /api/baseline`, query flag `baseline_only` on parents/events/export.
- Store filters events with `iso_micros(e.ts) > iso_micros(baseline)`.
- UI: “Baseline displayed entries”, “All activity” vs “Baseline / new”.

It does **not** yet:

- Snapshot “known entities” into a dedicated baseline set for fast delta queries.
- Suppress prompts/notifications for trusted activity.
- Send desktop notifications.
- Run domain recon beyond existing DNS tool-arg / optional PTR enrichment.

Future goals below build on this foundation without removing existing investigation features.

---

## Future goals (product roadmap)

Implement these on `dev` when tasked. Prefer **incremental PRs**, each with
tests and docs updates. Order is the preferred delivery sequence unless the
user re-prioritizes.

### Goal 1 — Baseline-backed local store; show only what is new (faster load)

**Intent:** After a baseline is set, persist enough state so the UI and API can
focus on **new** activity and load quickly, while **All activity** and full
investigation features remain available.

**Requirements:**

1. When baseline is set (or refreshed), capture a durable snapshot of the
   current evidence boundary in the local DB (not only a timestamp). Examples
   of snapshot candidates (design and choose deliberately): known process roots,
   destinations (domain/raddr/rport), event high-water marks (`max(event id)`),
   and/or process identity keys.
2. Default “Baseline / new” views must return **deltas only** (new roots,
   new events, new destinations) with indexes that avoid full-table scans of
   historical rows when possible.
3. Preserve existing capabilities: search, export, live/history/combined modes,
   advanced artifacts, clear baseline, clear evidence.
4. Measure success by **time-to-first-useful-paint / API latency** for the
   parents list and root detail under a large history DB—not by dropping data.

**Likely touch points:** `store.py`, `api.py`, `models.py`, frontend dashboard
refresh paths (`frontend/src/main.jsx`, `dashboard.js`, revision polling).

**Do not:** silently delete pre-baseline evidence; filter at documented
presentation/query boundaries only. Retention/prune rules stay explicit.

---

### Goal 2 — Desktop notifications on post-baseline network change

**Intent:** If network activity is observed that is **outside the baseline /
SAFE set**, notify the operator on the **desktop** (host OS notification).

**Requirements:**

1. Trigger only when baseline is active (or when an explicit “watch mode” is on
   if introduced—default to baseline-driven).
2. Notify on material network change: new destination, new connect/exec network
   tool activity, or new investigation root with network evidence—not every
   poll tick for the same live socket.
3. Deduplicate / coalesce notifications (rate-limit, fingerprint by
   root + destination + type) so the UI is not spammed.
4. Prefer a small, dependency-light Linux path (e.g. D-Bus / `notify-send`
   style) with graceful no-op when the desktop bus is unavailable (headless,
   SSH-only, container). Status/logging must explain why notifications are off.
5. Respect SAFE (Goal 4): SAFE-marked entities must **not** produce prompts.
6. Keep notifications **local**; no cloud push. No secrets in notification body
   (password, tokens, full cmdline if sensitive—prefer name, dest, pid).

**Likely touch points:** new notifier module under `src/igris/`, collector or
store hook after event insert, `config.py` toggles, optional UI settings.

---

### Goal 3 — Short-lived activity must be monitored

**Intent:** Activity that starts and ends quickly must still appear in the
evidence store when the environment allows.

**Requirements:**

1. Full mode (`ebpf+bcc`) remains the primary path for short-lived
   connect/exec/open; do not regress BCC collection or stack capture.
2. When eBPF is unavailable, improve polling where practical (intervals,
   process/network-tool edge detection) without claiming full coverage.
3. Health/status messages must continue to state visibility honestly
   (`full` vs `limited`) and what short-lived data may be missing.
4. Tests must cover short-lived process/network cases where they already exist
   (`tests/test_collectors.py`, `tests/test_ebpf.py`) and extend as behavior
   changes.

**Likely touch points:** `ebpf.py`, `collectors.py`, `main.py` collector
selection, packaging/eBPF install path.

---

### Goal 4 — Mark entries SAFE; suppress prompts for trusted activity

**Intent:** Operators can mark existing evidence entities as **SAFE**. Matching
future activity is still stored (investigation integrity) but is **not**
surfaced as alerts/prompts/highlight noise in “new” views.

**Requirements:**

1. User can mark an existing entry SAFE from the UI (and clear SAFE). Candidate
   entity keys (design explicitly—may combine):
   - process identity (exe path + hash when available)
   - destination (domain and/or raddr:rport)
   - investigation root / application name
2. SAFE state is persisted in SQLite (new table or preferences schema), survives
   restart, export-aware if needed, and is cleared on full evidence wipe only
   when product rules say so (document the choice).
3. While SAFE, activity:
   - **is still collected and queryable** in “All activity” / explicit SAFE
     filters;
   - **does not** trigger desktop notifications (Goal 2);
   - **does not** appear as “new / attention required” in baseline-delta views
     by default (with an optional “include SAFE” toggle if useful).
4. API surface should be explicit, e.g. mark/unmark SAFE and list SAFE entries.
5. SAFE is an **operator judgment**, not a security guarantee—label it as such
   in UI copy.

**Likely touch points:** `models.py`, `store.py`, `api.py`, frontend detail
panels and parent list badges.

---

### Goal 5 — Recon and info-gathering on observed domains

**Intent:** For domains seen in evidence, offer **local, on-demand** enrichment
to help investigation (not automatic scanning of the internet at full speed).

**Requirements:**

1. Recon runs against **observed domains** (from events / tool args), not
   arbitrary user-supplied target lists for offensive scanning.
2. Prefer passive/local enrichment first: existing DNS tool-arg, PTR (if
   enabled), then optional lookups such as DNS A/AAAA/MX/NS/TXT, WHOIS/RDAP
   where legally appropriate and dependency-light.
3. Cache results in SQLite with timestamps; do not re-query on every UI poll.
4. Clearly mark enrichment as **enriched** (not observed). Failures are soft:
   show “unavailable” without breaking the timeline.
5. Configurable: off by default or opt-in per host; rate-limited; no recursive
   crawling of unrelated infrastructure.
6. UI: domain detail panel or expandable row with recon summary + “refresh”.

**Likely touch points:** new recon helper module, `store.py` cache tables,
`api.py` endpoints, frontend advanced/domain UI, `config.py`.

**Do not:** turn Igris into a port scanner, vulnerability scanner, or
unauthorized recon platform. Stay investigation-scoped and local-first.

---

## How agents should implement work

1. Confirm branch (`dev` unless told otherwise) and read the files that own the
   behavior.
2. Prefer the **smallest complete change** in the correct layer.
3. Add/update tests for every behavior change (backend + frontend as needed).
4. Keep auth, host/origin checks, cache-control, export escaping, and
   evidence semantics intact.
5. Rebuild frontend through `npm run build` / installer—never hand-edit
   `src/igris/static` or commit `node_modules` / `frontend/dist`.
6. Run verification:
   - focused: `pytest` / frontend unit tests for touched code;
   - broader: `./tests/all.sh` before claiming done;
   - security-sensitive: `./tests/security.sh` when relevant.
7. Do not commit secrets, DB files, verifiers, or local `.env`.
8. Do not run destructive ops against `/opt/igris`, the live DB, or systemd
   unless the user explicitly authorizes it.
9. Handoff: what changed, tests run, remaining limits, and any follow-up for
   the roadmap goals.

### Definition of done (summary)

- Requested behavior in the correct layer  
- Tests pass for new/changed paths  
- No silent evidence loss or security regression  
- Frontend static tree synchronized when UI changed  
- Docs updated when API or operator workflow changes  
  (README and this file / DEVELOPMENT_INSTRUCTIONS as appropriate)

---

## Quick commands

```bash
# Backend dev install
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/igrisd

# Frontend
cd frontend && npm ci && npm test && npm run build && cd ..
diff -qr frontend/dist src/igris/static

# Full local CI suite
./tests/all.sh
```

---

## Out of scope (unless explicitly requested)

- Cloud backends, multi-host fleet SIEM, or remote agent mesh  
- Firewall / IPS blocking actions  
- TLS interception or packet capture pipeline  
- Automated malware classification as ground truth  
- Weakening auth or binding to `0.0.0.0` by default  

When unsure, ask the user before expanding scope beyond the goals above.
