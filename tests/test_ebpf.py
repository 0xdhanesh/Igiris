from pathlib import Path

from igiris import ebpf


def test_bpf_program_uses_bcc_stack_trace_map_helper():
    assert "user_stacks.get_stackid(" in ebpf.BPF_PROGRAM
    assert "bpf_get_stackid(" not in ebpf.BPF_PROGRAM


def test_stack_trace_resolution_uses_bcc_walk_and_symbol_cache():
    class StackMap:
        def walk(self, stack_id):
            assert stack_id == 4
            return iter([0x1010, 0x2020])
    class Cache:
        def resolve(self,address,demangle):
            assert demangle is True
            return ((b"SSL_connect",0x10,b"/usr/lib/libssl.so.3")
                if address==0x1010 else (None,0x20,b"/usr/lib/libc.so.6"))
    class FakeBpf:
        def __getitem__(self,name):
            assert name=="user_stacks"
            return StackMap()
        def _sym_cache(self,pid):
            assert pid==42
            return Cache()
    collector=object.__new__(ebpf.BccCollector)
    collector._bpf=FakeBpf()

    assert collector._resolve_stack_trace(42,4)==[
        {"library":"/usr/lib/libssl.so.3","symbol":"SSL_connect","offset":"0x10","raw_ip":"0x1010"},
        {"library":"/usr/lib/libc.so.6","symbol":None,"offset":"0x20","raw_ip":"0x2020"},
    ]


def test_bcc_readiness_reports_missing_kernel_headers(monkeypatch):
    monkeypatch.setattr(ebpf.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ebpf.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(ebpf.platform, "uname", lambda: type("Uname", (), {"release": "test-kernel"})())
    monkeypatch.setattr(Path, "exists", lambda self: False)

    ready, messages = ebpf.bcc_readiness()

    assert ready is False
    assert "Matching kernel headers are unavailable" in messages[0]
    assert "/lib/modules/test-kernel/build" in messages[0]


def test_bcc_readiness_accepts_build_headers(monkeypatch):
    monkeypatch.setattr(ebpf.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ebpf.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(ebpf.platform, "uname", lambda: type("Uname", (), {"release": "test-kernel"})())
    monkeypatch.setattr(Path, "exists", lambda self: str(self).endswith("/build"))

    assert ebpf.bcc_readiness() == (True, [])
