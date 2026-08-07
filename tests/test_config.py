import pytest

from igris.config import Settings


def test_network_bind_mode_resolves_to_all_interfaces(monkeypatch):
    monkeypatch.setenv("IGRIS_BIND_MODE", "network")
    monkeypatch.delenv("IGRIS_BIND_HOST", raising=False)

    settings = Settings(_env_file=None)

    assert settings.resolved_bind_host == "0.0.0.0"


def test_bind_mode_defaults_to_localhost(monkeypatch):
    monkeypatch.delenv("IGRIS_BIND_MODE", raising=False)
    monkeypatch.delenv("IGRIS_BIND_HOST", raising=False)

    settings = Settings(_env_file=None)

    assert settings.resolved_bind_host == "127.0.0.1"


def test_explicit_bind_host_takes_precedence_over_bind_mode(monkeypatch):
    monkeypatch.setenv("IGRIS_BIND_MODE", "network")
    monkeypatch.setenv("IGRIS_BIND_HOST", "127.0.0.2")

    settings = Settings(_env_file=None)

    assert settings.resolved_bind_host == "127.0.0.2"


def test_invalid_bind_mode_warns_and_falls_back_to_localhost(monkeypatch):
    monkeypatch.setenv("IGRIS_BIND_MODE", "internet")
    monkeypatch.delenv("IGRIS_BIND_HOST", raising=False)

    with pytest.warns(RuntimeWarning, match="Invalid IGRIS_BIND_MODE"):
        settings = Settings(_env_file=None)

    assert settings.resolved_bind_host == "127.0.0.1"
