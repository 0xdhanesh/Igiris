from igris.config import Settings
from igris import main


def test_run_uses_resolved_bind_host(monkeypatch, tmp_path):
    settings = Settings(
        bind_mode="network",
        database_path=str(tmp_path / "igris.db"),
        collector_enabled=False,
        _env_file=None,
    )
    run_arguments = {}
    monkeypatch.setattr(main, "Settings", lambda: settings)
    monkeypatch.setattr(
        main.uvicorn,
        "run",
        lambda app, **kwargs: run_arguments.update(kwargs),
    )

    main.run()

    assert run_arguments["host"] == "0.0.0.0"


def test_run_prints_selected_bind_address(monkeypatch, tmp_path, capsys):
    settings = Settings(
        bind_mode="network",
        database_path=str(tmp_path / "igris.db"),
        collector_enabled=False,
        _env_file=None,
    )
    monkeypatch.setattr(main, "Settings", lambda: settings)
    monkeypatch.setattr(main.uvicorn, "run", lambda app, **kwargs: None)

    main.run()

    assert "Starting Igris on 0.0.0.0:8787" in capsys.readouterr().err
