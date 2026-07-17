from dataclasses import dataclass
from types import SimpleNamespace
from datetime import datetime, timezone
import socket

from igiris.collectors import DomainCorrelator, PollingCollector, connection_to_event, detect_new_network_tools, dns_query_from_tool, historical_transitions, is_internal_api_connection, observed_domain_from_tool, persist_lineage
from igiris.ebpf import BPF_PROGRAM
from igiris.store import Store
from igiris.processes import ProcessSnapshot


@dataclass
class Addr:
    ip: str
    port: int

@dataclass
class Conn:
    family: int
    type: int
    raddr: Addr
    status: str
    pid: int
    laddr: Addr | None = None


def table():
    return {
        20: ProcessSnapshot(20, 10, "curl", "/usr/bin/curl", "curl https://example.test", "analyst"),
        10: ProcessSnapshot(10, 1, "bash", "/usr/bin/bash", "bash", "analyst"),
    }


def test_connection_to_event_preserves_ipv6_and_parent_attribution():
    conn = Conn(socket.AF_INET6, socket.SOCK_STREAM, Addr("2001:db8::2", 443), "ESTABLISHED", 20)
    event, process = connection_to_event(conn, table(), DomainCorrelator())
    assert event.family == "ipv6"
    assert event.root_pid == 10
    assert event.pid == 20
    assert event.raddr == "2001:db8::2"
    assert process.name == "curl"


def test_observed_dns_is_preferred_and_scoped_to_pid():
    correlator = DomainCorrelator()
    correlator.observe(pid=20, domain="payload.example", addresses=["203.0.113.8"])
    assert correlator.lookup(20, "203.0.113.8") == ("payload.example", "observed_dns")
    assert correlator.lookup(21, "203.0.113.8") == (None, "none")


def test_new_network_tool_execs_are_tagged_once():
    previous = {10}
    current = table()
    found = detect_new_network_tools(previous, current, {"curl", "wget"})
    assert [item.pid for item in found] == [20]


def test_dns_tool_query_name_is_observable_from_exec():
    snapshot = ProcessSnapshot(30, 10, "dig", "/usr/bin/dig", "dig +short payload.example A", "analyst")
    assert dns_query_from_tool(snapshot) == "payload.example"


def test_url_hostname_is_observable_from_curl_and_wget_exec():
    curl = ProcessSnapshot(30, 10, "curl", "/usr/bin/curl", "curl -L https://0xdhanesh.github.io/path?q=1", "analyst")
    wget = ProcessSnapshot(31, 10, "wget", "/usr/bin/wget", "wget --quiet https://example.net/file", "analyst")
    assert observed_domain_from_tool(curl) == ("0xdhanesh.github.io", "observed_tool_arg")
    assert observed_domain_from_tool(wget) == ("example.net", "observed_tool_arg")


def test_curl_socket_inherits_hostname_observed_in_its_command_line():
    conn = Conn(socket.AF_INET6, socket.SOCK_STREAM, Addr("2606:50c0:8002::153", 443), "ESTABLISHED", 20)
    event, _ = connection_to_event(conn, table(), DomainCorrelator())
    assert event.domain == "example.test"
    assert event.domain_source == "observed_tool_arg"


def test_history_transition_records_reconnect_after_close():
    key = (20, "ipv4", "tcp", "203.0.113.8", 443)
    assert historical_transitions(set(), {key}) == {key}
    assert historical_transitions({key}, {key}) == set()
    assert historical_transitions(set(), {key}) == {key}


def test_inbound_and_local_outbound_igiris_api_sockets_are_not_collected_as_evidence():
    inbound = Conn(socket.AF_INET, socket.SOCK_STREAM, Addr("192.168.1.23", 51000), "ESTABLISHED", 40, Addr("0.0.0.0", 8787))
    outbound_remote = Conn(socket.AF_INET, socket.SOCK_STREAM, Addr("203.0.113.8", 8787), "ESTABLISHED", 40, Addr("192.168.1.22", 51000))
    outbound_local = Conn(socket.AF_INET, socket.SOCK_STREAM, Addr("192.168.1.22", 8787), "ESTABLISHED", 40, Addr("192.168.1.22", 51000))
    outbound_loopback = Conn(socket.AF_INET, socket.SOCK_STREAM, Addr("127.0.0.1", 8787), "ESTABLISHED", 40, Addr("127.0.0.1", 51000))
    assert is_internal_api_connection(inbound, 8787, {"192.168.1.22"})
    assert not is_internal_api_connection(outbound_remote, 8787, {"192.168.1.22"})
    assert is_internal_api_connection(outbound_local, 8787, {"192.168.1.22"})
    assert is_internal_api_connection(outbound_loopback, 8787, {"192.168.1.22"})


def test_collector_tracking_resets_when_evidence_is_cleared():
    collector = PollingCollector(None, SimpleNamespace(bind_port=8787), {})
    collector._seen = {20}
    collector._historical = {(20, "ipv4", "tcp", "203.0.113.8", 443)}
    collector.domains.observe(20, "example.test", ["203.0.113.8"])

    collector.reset_tracking()

    assert collector._seen == set()
    assert collector._historical == set()
    assert collector.domains.lookup(20, "203.0.113.8") == (None, "none")


def test_bpf_connect_uses_syscall_entry_and_exit_sockaddr_capture():
    assert "TRACEPOINT_PROBE(syscalls, sys_enter_connect)" in BPF_PROGRAM
    assert "TRACEPOINT_PROBE(syscalls, sys_exit_connect)" in BPF_PROGRAM
    assert "tcp_v4_connect" not in BPF_PROGRAM


def test_persist_lineage_keeps_meaningful_root_identity(tmp_path):
    store = Store(tmp_path / "lineage.db")
    store.initialize()
    persist_lineage(store, 20, table(), 10)
    nodes = store.list_processes(10)
    assert [(node.pid, node.name) for node in nodes] == [(10, "bash"), (20, "curl")]
    store.close()
