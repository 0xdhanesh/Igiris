import csv
import io

from igiris.models import Event, ProcessArtifact, ProcessNode
from datetime import datetime, timezone


def seed(store):
    now = datetime.now(timezone.utc)
    store.upsert_process(ProcessNode(pid=7, ppid=1, root_pid=7, name="wget", exe_path="/usr/bin/wget", exe_hash=None, user="analyst", cmdline="wget x", first_seen=now, last_seen=now))
    store.add_event(Event(ts=now, type="connect", pid=7, root_pid=7, exe_path="/usr/bin/wget", family="ipv6", protocol="tcp", raddr="2001:db8::1", rport=443, domain="example.test", domain_source="observed_dns", raw_meta={}))


def test_parent_detail_contains_tree_and_events(client, store):
    seed(store)
    response = client.get("/api/parents/7")
    assert response.status_code == 200
    body = response.json()
    assert body["parent"]["name"] == "wget"
    assert body["events"][0]["family"] == "ipv6"
    assert body["processes"][0]["exe_hash"] is None


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
    assert body["files"][0]["path"] == "/etc/resolv.conf"
    assert (body["network"][0]["domain"], body["network"][0]["raddr"]) == ("google.com", "142.250.70.14")
    assert body["evidence_semantics"]["file_visibility"] == "observed_snapshot"
    assert client.get("/api/parents/7/processes/999/advanced").status_code == 404
    assert client.get("/api/parents/99/processes/8/advanced").status_code == 404


def test_csv_export_is_evidence_ready(client, store):
    seed(store)
    response = client.get("/api/export.csv?root_pid=7")
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows[0]["domain"] == "example.test"
    assert rows[0]["raddr"] == "2001:db8::1"


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


def test_api_token_and_origin_protect_evidence(store):
    from fastapi.testclient import TestClient
    from igiris.api import create_app
    from igiris.config import Settings
    app = create_app(Settings(database_path=str(store.path), static_dir="missing", collector_enabled=False, allowed_hosts="testserver", api_token="test-secret"), store)
    secured = TestClient(app)
    assert secured.get("/api/health").status_code == 401
    assert secured.delete("/api/evidence").status_code == 401
    headers = {"Authorization": "Bearer test-secret"}
    assert secured.get("/api/health", headers=headers).status_code == 200
    assert secured.get("/api/health", headers={**headers, "Origin": "http://evil.test"}).status_code == 403
