from datetime import datetime, timezone

from igris.models import Event, ProcessArtifact, ProcessNode


def node(pid: int = 42, root_pid: int = 42) -> ProcessNode:
    now = datetime.now(timezone.utc)
    return ProcessNode(pid=pid, ppid=1, root_pid=root_pid, name="curl", exe_path="/usr/bin/curl", exe_hash="abc123", user="analyst", cmdline="curl https://example.com", first_seen=now, last_seen=now)


def event(pid: int = 42, root_pid: int = 42, domain: str = "example.com") -> Event:
    return Event(ts=datetime.now(timezone.utc), type="connect", pid=pid, root_pid=root_pid, exe_path="/usr/bin/curl", exe_hash="abc123", family="ipv4", protocol="tcp", raddr="93.184.216.34", rport=443, domain=domain, domain_source="observed_dns", success=True, raw_meta={"source": "test"})


def test_store_builds_parent_summary_and_searches_destinations(store):
    store.upsert_process(node())
    store.add_event(event())
    parents = store.list_parents(search="example.com")
    assert len(parents) == 1
    assert parents[0].root_pid == 42
    assert parents[0].history_event_count == 1
    assert parents[0].unique_destination_count == 1
    assert parents[0].top_destinations == ["example.com"]
    assert parents[0].latest_persistent_event_id > 0


def test_store_persists_deduplicated_advanced_process_artifacts(store):
    now = datetime.now(timezone.utc)
    store.upsert_process(node())
    library = ProcessArtifact(pid=42, root_pid=42, kind="library", path="/usr/lib/libssl.so.3", source="proc_maps", first_seen=now, last_seen=now)
    opened = ProcessArtifact(pid=42, root_pid=42, kind="file", path="/etc/ssl/openssl.cnf", source="proc_fd", first_seen=now, last_seen=now)
    store.upsert_artifacts([library, opened, library])
    artifacts = store.list_artifacts(42, 42)
    assert [(item.kind, item.path, item.source) for item in artifacts] == [
        ("file", "/etc/ssl/openssl.cnf", "proc_fd"),
        ("library", "/usr/lib/libssl.so.3", "proc_maps"),
    ]


def test_store_returns_selected_process_command_subtree(store):
    now = datetime.now(timezone.utc)
    for process in [
        ProcessNode(pid=40, ppid=1, root_pid=40, name="bash", cmdline="bash", first_seen=now, last_seen=now),
        ProcessNode(pid=41, ppid=40, root_pid=40, name="python", cmdline="python app.py", first_seen=now, last_seen=now),
        ProcessNode(pid=42, ppid=41, root_pid=40, name="curl", cmdline="curl https://example.com", first_seen=now, last_seen=now),
        ProcessNode(pid=43, ppid=40, root_pid=40, name="sleep", cmdline="sleep 10", first_seen=now, last_seen=now),
    ]:
        store.upsert_process(process)
    assert [process.pid for process in store.list_process_subtree(40, 41)] == [41, 42]


def test_parent_search_returns_every_root_matching_parent_child_pid_or_ip(store):
    now = datetime.now(timezone.utc)
    processes = [
        ProcessNode(pid=100, ppid=1, root_pid=100, name="python3", exe_path="/usr/bin/python3", exe_hash="root-a", user="analyst", cmdline="python3 app.py", first_seen=now, last_seen=now),
        ProcessNode(pid=101, ppid=100, root_pid=100, name="curl", exe_path="/usr/bin/curl", exe_hash="curl-a", user="analyst", cmdline="curl https://child.example", first_seen=now, last_seen=now),
        ProcessNode(pid=200, ppid=1, root_pid=200, name="curl", exe_path="/opt/curl", exe_hash="root-b", user="analyst", cmdline="curl https://root.example", first_seen=now, last_seen=now),
        ProcessNode(pid=300, ppid=1, root_pid=300, name="wget", exe_path="/usr/bin/wget", exe_hash="root-c", user="analyst", cmdline="wget https://other.example", first_seen=now, last_seen=now),
    ]
    for process in processes:
        store.upsert_process(process)
    parent_event = event(pid=100, root_pid=100, domain="parent.example")
    parent_event.exe_path = "/usr/bin/python3"
    parent_event.exe_hash = "root-a"
    store.add_event(parent_event)
    store.add_event(event(pid=200, root_pid=200, domain="root.example"))
    ip_event = event(pid=300, root_pid=300, domain="other.example")
    ip_event.exe_path = "/usr/bin/wget"
    ip_event.exe_hash = "root-c"
    ip_event.raddr = "203.0.113.77"
    store.add_event(ip_event)

    assert {parent.root_pid for parent in store.list_parents(search="curl")} == {100, 200}
    assert [parent.root_pid for parent in store.list_parents(search="101")] == [100]
    assert [parent.root_pid for parent in store.list_parents(search="203.0.113.77")] == [300]
    assert all(parent.history_event_count == 1 for parent in store.list_parents(search="curl"))


def test_baseline_filters_old_events(store):
    process = node()
    old = event(domain="old.example")
    store.upsert_process(process)
    store.add_event(old)
    store.set_baseline(datetime.now(timezone.utc))
    assert store.list_parents(baseline_only=True) == []
    store.add_event(event(domain="new.example"))
    assert store.list_parents(baseline_only=True)[0].top_destinations == ["new.example"]


def test_baseline_new_view_is_strictly_newer_than_displayed_boundary(store):
    from datetime import timedelta
    boundary = datetime.now(timezone.utc)
    store.upsert_process(node())
    current = event(domain="current.example")
    current.ts = boundary
    store.add_event(current)
    store.set_baseline(boundary)
    assert store.list_parents(baseline_only=True) == []
    later = event(domain="later.example")
    later.ts = boundary + timedelta(seconds=1)
    store.add_event(later)
    assert store.list_parents(baseline_only=True)[0].top_destinations == ["later.example"]


def test_retention_removes_expired_events(store):
    from datetime import timedelta
    process = node()
    expired = event()
    expired.ts = datetime.now(timezone.utc) - timedelta(hours=25)
    store.upsert_process(process)
    store.add_event(expired)
    assert store.prune(retention_hours=24) == 1
    assert store.list_events(root_pid=42) == []


def test_soft_cap_prunes_oldest_evidence(store):
    store.upsert_process(node())
    for index in range(20):
        item = event(domain=f"{index}.example")
        item.raw_meta = {"padding": "x" * 2000}
        store.add_event(item)
    removed = store.prune_to_cap(max_bytes=1)
    assert removed == 20
    assert store.list_events(root_pid=42) == []


def test_clear_all_evidence_removes_network_history_processes_and_baseline(store):
    store.upsert_process(node())
    store.add_event(event())
    now = datetime.now(timezone.utc)
    store.upsert_artifacts([ProcessArtifact(pid=42, root_pid=42, kind="file", path="/tmp/evidence", source="proc_fd", first_seen=now, last_seen=now)])
    store.set_baseline(datetime.now(timezone.utc))

    removed = store.clear_all_evidence()

    assert removed == {"events": 1, "processes": 1, "artifacts": 1}
    assert store.list_events() == []
    assert store.list_processes(42) == []
    assert store.list_artifacts(42, 42) == []
    assert store.get_baseline() is None


def test_database_file_is_owner_only(store):
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_data_revision_changes_for_new_evidence_but_not_live_row_reinsertion(store):
    store.upsert_process(node())
    initial = store.data_revision()
    store.add_event(event(domain="persistent.example"))
    persistent = store.data_revision()
    assert persistent != initial

    live = event(domain="live.example")
    live.type = "live_socket"
    store.replace_live_events([live])
    first_live = store.data_revision()
    assert first_live != persistent

    live.id = None
    store.replace_live_events([live])
    assert store.data_revision() == first_live
