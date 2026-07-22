from pathlib import Path

from igiris import ebpf


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
