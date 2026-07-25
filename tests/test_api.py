import csv
import io
import threading
from concurrent.futures import ThreadPoolExecutor

from igiris.models import Event, ProcessArtifact, ProcessNode
from datetime import datetime, timezone


def seed(store):
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=7, ppid=1, root_pid=7, name="wget", exe_path="/usr/bin/wget", exe_hash=None, user="analyst", cmdline="wget x", first_seen=now, last_seen=now))
    store.add_event(Event(ts=now, type="connect", pid=7, root_pid=7, exe_path="/usr/bin/wget", family="ipv6", protocol="tcp", raddr="2001:db8::1", rport=443, domain="example.test", domain_source="observed_dns", raw_meta={}))


def test_parent_detail_contains_tree_and_events(client, store):
    seed(store)
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=99, ppid=7, root_pid=7, name="unrelated", exe_path="/usr/bin/unrelated", exe_hash=None, user="analyst", cmdline="unrelated", first_seen=now, last_seen=now))
    response = client.get("/api/parents/7")
    assert response.status_code == 200
    body = response.json()
    assert body["parent"]["name"] == "wget"
    assert body["events"][0]["family"] == "ipv6"
    assert body["processes"][0]["exe_hash"] is None
    assert [process["pid"] for process in body["processes"]] == [7]


def test_parent_detail_keeps_ancestors_between_root_and_network_child(client, store):
    seed(store)
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=8, ppid=7, root_pid=7, name="beru_demo", exe_path="/tmp/beru_demo", exe_hash=None, user="analyst", cmdline="beru_demo", first_seen=now, last_seen=now))
    store.upsert_process(ProcessNode(pid=9, ppid=8, root_pid=7, name="ping", exe_path="/usr/bin/ping", exe_hash=None, user="analyst", cmdline="ping example.net", first_seen=now, last_seen=now))
    store.add_event(Event(ts=now, type="icmp", pid=9, root_pid=7, exe_path="/usr/bin/ping", family="ipv4", protocol="icmp", domain="example.net", domain_source="observed_tool_arg", raw_meta={}))
    body = client.get("/api/parents/7").json()
    assert [(process["pid"], process["name"]) for process in body["processes"]] == [
        (7, "wget"), (8, "beru_demo"), (9, "ping"),
    ]
    assert body["processes"][1]["subtree_event_count"] == 1
    assert [(event["pid"],event["domain"]) for event in body["process_events"]["8"]] == [(9,"example.net")]
    subtree = client.get("/api/events?root_pid=7&pid=8&include_descendants=true").json()
    assert [(event["pid"], event["domain"]) for event in subtree] == [(9, "example.net")]


def test_events_can_be_filtered_to_a_selected_process(client, store):
    seed(store)
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=8, ppid=7, root_pid=7, name="python3", exe_path="/usr/bin/python3", exe_hash="python-hash", user="analyst", cmdline="python3 -c request", first_seen=now, last_seen=now))
    store.add_event(Event(ts=now, type="connect", pid=8, root_pid=7, exe_path="/usr/bin/python3", family="ipv4", protocol="tcp", raddr="142.250.70.14", rport=443, domain="google.com", domain_source="observed_dns", raw_meta={}))
    response = client.get("/api/events?root_pid=7&pid=8&mode=history&limit=50")
    assert response.status_code == 200
    assert [(event["pid"], event["domain"]) for event in response.json()] == [(8, "google.com")]


def test_advanced_process_evidence_combines_ioc_commands_artifacts_and_domain_ip(client, store):
    seed(store)
    now = datetime.now(timezone.utc)
    child = ProcessNode(pid=8, ppid=7, root_pid=7, name="python3", exe_path="/usr/bin/python3", exe_hash="python-hash", user="analyst", cmdline="python3 implant.py", first_seen=now, last_seen=now)
    store.upsert_process(child)
    store.upsert_artifacts([
        ProcessArtifact(pid=8, root_pid=7, kind="library", path="/usr/lib/libssl.so.3", source="proc_maps", first_seen=now, last_seen=now),
        ProcessArtifact(pid=8, root_pid=7, kind="file", path="/etc/resolv.conf", source="proc_fd", first_seen=now, last_seen=now),
    ])
    store.add_event(Event(ts=now, type="connect", pid=8, root_pid=7, exe_path=child.exe_path, exe_hash=child.exe_hash, family="ipv4", protocol="tcp", raddr="142.250.70.14", rport=443, domain="google.com", domain_source="observed_dns", raw_meta={"source":"test"}))
    response = client.get("/api/parents/7/processes/8/advanced")
    assert response.status_code == 200
    body = response.json()
    assert body["process"]["exe_hash"] == "python-hash"
    assert body["commands"][0]["cmdline"] == "python3 implant.py"
    assert body["libraries"][0]["path"] == "/usr/lib/libssl.so.3"
    assert body["libraries"][0]["network_related"] is False
    assert body["files"][0]["path"] == "/etc/resolv.conf"
    assert (body["network"][0]["domain"], body["network"][0]["raddr"]) == ("google.com", "142.250.70.14")
    assert body["evidence_semantics"]["file_visibility"] == "observed_snapshot"
    assert client.get("/api/parents/7/processes/999/advanced").status_code == 404
    assert client.get("/api/parents/99/processes/8/advanced").status_code == 404


def test_advanced_evidence_reports_kernel_stream_when_ebpf_is_active(client, store):
    seed(store)
    client.app.state.collector_status.update({"mode":"ebpf+bcc","visibility":"full","ebpf_available":True})
    body=client.get("/api/parents/7/processes/7/advanced").json()
    assert body["evidence_semantics"]["file_visibility"] == "kernel_events"
    assert "short-lived activity can be missed" not in body["evidence_semantics"]["warning"]


def test_advanced_library_payload_exposes_network_related_marker(client, store):
    seed(store)
    now = datetime.now(timezone.utc)
    store.upsert_artifacts([ProcessArtifact(pid=7, root_pid=7, kind="library", path="/usr/lib/libcurl.so.4", source="ebpf_open_before_connect", first_seen=now, last_seen=now)])
    body=client.get("/api/parents/7/processes/7/advanced").json()
    assert body["libraries"][0]["network_related"] is True


def test_advanced_library_payload_correlates_offsets_and_full_stack(client, store):
    seed(store)
    now=datetime.now(timezone.utc)
    store.upsert_artifacts([ProcessArtifact(pid=7,root_pid=7,kind="library",path="/usr/lib/libssl.so.3",source="proc_maps",first_seen=now,last_seen=now)])
    frames=[
        {"library":"/usr/lib/libssl.so.3","symbol":"SSL_connect","offset":"0x2a","raw_ip":"0x1010"},
        {"library":"/usr/lib/libc.so.6","symbol":"connect","offset":"0x10","raw_ip":"0x2020"},
    ]
    store.add_event(Event(ts=now,type="connect",pid=7,root_pid=7,exe_path="/usr/bin/wget",family="ipv4",protocol="ip-connect",raddr="192.0.2.1",rport=443,domain_source="none",raw_meta={"stack_trace":frames}))

    library=client.get("/api/parents/7/processes/7/advanced").json()["libraries"][0]

    assert library["network_related"] is True
    assert library["stack_traces"][0]["frames"]==frames
    assert library["stack_traces"][0]["attributed_frames"]==[frames[0]]


def test_parent_library_is_correlated_to_descendant_exec_caller_stack(client, store):
    seed(store)
    now=datetime.now(timezone.utc)
    child=ProcessNode(pid=8,ppid=7,root_pid=7,name="ping",exe_path="/usr/bin/ping",exe_hash=None,user="analyst",cmdline="ping example.test",first_seen=now,last_seen=now)
    store.upsert_process(child)
    store.upsert_artifacts([ProcessArtifact(pid=7,root_pid=7,kind="library",path="/tmp/libberu.so",source="ebpf_execve_caller_stack",first_seen=now,last_seen=now)])
    frame={"library":"/tmp/libberu.so","symbol":"beru_ping","offset":"0x2a","raw_ip":"0x1010"}
    store.add_event(Event(ts=now,type="exec_network_tool",pid=8,root_pid=7,exe_path="/usr/bin/ping",family="unknown",domain="example.test",domain_source="observed_tool_arg",raw_meta={"exec_stack_trace":[frame],"exec_call_site":frame}))

    body=client.get("/api/parents/7/processes/7/advanced").json()

    assert body["network"][0]["pid"] == 8
    assert body["libraries"][0]["network_related"] is True
    assert body["libraries"][0]["stack_traces"][0]["attributed_frames"] == [frame]


def test_csv_export_is_evidence_ready(client, store):
    seed(store)
    response = client.get("/api/export.csv?root_pid=7")
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows[0]["domain"] == "example.test"
    assert rows[0]["raddr"] == "2001:db8::1"


def test_csv_export_neutralizes_spreadsheet_formula_cells(client, store):
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=9, ppid=1, root_pid=9, name="formula-test", exe_path="=cmd|' /C calc'!A0", exe_hash=None, user="analyst", cmdline="formula-test", first_seen=now, last_seen=now))
    store.add_event(Event(ts=now, type="connect", pid=9, root_pid=9, exe_path="=cmd|' /C calc'!A0", family="ipv4", protocol="tcp", raddr="+1+1", rport=443, domain="@SUM(1,1)", domain_source="observed_dns", raw_meta={}))

    response = client.get("/api/export.csv?root_pid=9")
    row = next(csv.DictReader(io.StringIO(response.text)))

    assert row["exe_path"] == "'=cmd|' /C calc'!A0"
    assert row["raddr"] == "'+1+1"
    assert row["domain"] == "'@SUM(1,1)"


def test_all_api_responses_are_not_cacheable(client, store):
    seed(store)

    for path in ("/api", "/api/health", "/api/events", "/api/export.json", "/api/export.csv", "/api/not-found"):
        response = client.get(path)
        assert response.headers["Cache-Control"] == "no-store"


def test_unhandled_api_errors_are_not_cacheable(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.config import Settings

    app = create_app(Settings(database_path=str(store.path), static_dir="missing", collector_enabled=False, allowed_hosts="testserver"), store)

    @app.get("/api/explode")
    def explode():
        raise RuntimeError("intentional test exception")

    response = TestClient(app, raise_server_exceptions=False).get("/api/explode")

    assert response.status_code == 500
    assert response.headers["Cache-Control"] == "no-store"


def test_export_honors_view_and_destination_filters(client, store):
    seed(store)
    response = client.get("/api/export.json?root_pid=7&mode=history&destination=example.test")
    assert response.status_code == 200
    assert [event["domain"] for event in response.json()] == ["example.test"]
    assert client.get("/api/export.json?root_pid=7&mode=live&destination=example.test").json() == []


def test_clear_evidence_endpoint_starts_with_an_empty_store(client, store):
    seed(store)
    store.set_baseline(datetime.now(timezone.utc))
    response = client.delete("/api/evidence")
    assert response.status_code == 200
    assert response.json() == {"cleared": {"events": 1, "processes": 1, "artifacts": 0}}
    assert client.get("/api/parents").json() == []
    assert client.get("/api/health").json()["baseline_ts"] is None


def test_health_reports_limited_visibility(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert "visibility" in body


def test_revision_endpoint_changes_when_new_evidence_arrives(client, store):
    before = client.get("/api/revision").json()["revision"]
    seed(store)
    after = client.get("/api/revision").json()["revision"]
    assert after != before


def test_api_rejects_untrusted_host(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.config import Settings
    app = create_app(Settings(database_path=str(store.path), static_dir="missing", collector_enabled=False, allowed_hosts="127.0.0.1"), store)
    assert TestClient(app, base_url="http://attacker.test").get("/api/health").status_code == 400


def test_password_login_session_logout_and_origin_protect_evidence(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.auth import hash_password
    from igiris.config import Settings

    app = create_app(
        Settings(
            database_path=str(store.path),
            static_dir="missing",
            collector_enabled=False,
            allowed_hosts="testserver",
            password_verifier=hash_password("test password"),
            session_ttl_seconds=300,
        ),
        store,
    )
    secured = TestClient(app)

    unauthorized = secured.get("/api/health")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["Cache-Control"] == "no-store"
    assert secured.delete("/api/evidence").status_code == 401
    assert secured.post("/api/auth/login", json={"password": "wrong"}).status_code == 401
    assert secured.post(
        "/api/auth/login",
        json={"password": "test password"},
        headers={"Origin": "http://evil.test"},
    ).status_code == 403

    login = secured.post("/api/auth/login", json={"password": "test password"})
    assert login.status_code == 200
    assert login.json()["expires_in"] == 300
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert secured.get("/api/health", headers=headers).status_code == 200

    assert secured.post("/api/auth/logout", headers=headers).status_code == 204
    assert secured.get("/api/health", headers=headers).status_code == 401


def test_non_ascii_bearer_credential_is_rejected_as_unauthorized(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.auth import hash_password
    from igiris.config import Settings

    app = create_app(Settings(database_path=str(store.path), static_dir="missing",
        collector_enabled=False, allowed_hosts="testserver",
        password_verifier=hash_password("test password")), store)

    response = TestClient(app).get("/api/health", headers={b"Authorization": b"Bearer caf\xe9"})

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_password_login_throttles_repeated_failures(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.auth import hash_password
    from igiris.config import Settings

    app = create_app(
        Settings(
            database_path=str(store.path),
            static_dir="missing",
            collector_enabled=False,
            allowed_hosts="testserver",
            password_verifier=hash_password("test password"),
            login_max_failures=2,
            login_failure_window_seconds=60,
        ),
        store,
    )
    secured = TestClient(app)

    assert secured.post("/api/auth/login", json={"password": "wrong"}).status_code == 401
    assert secured.post("/api/auth/login", json={"password": "wrong again"}).status_code == 401
    blocked = secured.post("/api/auth/login", json={"password": "test password"})
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "60"


def test_parallel_logins_bound_expensive_password_checks(store, monkeypatch):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.config import Settings

    entered = 0
    entered_lock = threading.Lock()
    release = threading.Event()

    def slow_verify(_password, _verifier):
        nonlocal entered
        with entered_lock:
            entered += 1
        release.wait(timeout=2)
        return False

    monkeypatch.setattr("igiris.api.verify_password", slow_verify)
    app = create_app(Settings(database_path=str(store.path), static_dir="missing",
        collector_enabled=False, allowed_hosts="testserver", password_verifier="configured",
        login_max_failures=10, login_failure_window_seconds=60, login_max_parallel_checks=2), store)

    def login():
        return TestClient(app).post("/api/auth/login", json={"password": "wrong"})

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(login) for _ in range(6)]
        assert threading.Event().wait(0.1) is False
        release.set()
        responses = [future.result() for future in futures]

    assert entered == 2
    assert sorted(response.status_code for response in responses) == [401, 401, 429, 429, 429, 429]
