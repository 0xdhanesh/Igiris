from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_packaging_uses_password_verifier_without_random_api_token():
    installer = (ROOT / "packaging" / "install.sh").read_text()
    environment = (ROOT / "packaging" / "igiris.env").read_text()
    project = (ROOT / "pyproject.toml").read_text()

    assert "api.token" not in installer
    assert "token_urlsafe" not in installer
    assert "igiris-set-password" in installer
    assert "IGIRIS_PASSWORD_VERIFIER_FILE=/etc/igiris/password.verifier" in environment
    assert "IGIRIS_LOGIN_MAX_PARALLEL_CHECKS=2" in environment
    assert "IGIRIS_API_TOKEN" not in environment
    assert 'igiris-set-password = "igiris.auth_cli:main"' in project


def test_installer_restarts_an_already_running_service_after_upgrade():
    installer = (ROOT / "packaging" / "install.sh").read_text()

    assert "systemctl is-active --quiet igiris" in installer
    assert "systemctl restart igiris" in installer


def test_installer_preserves_existing_environment_configuration():
    installer = (ROOT / "packaging" / "install.sh").read_text()

    assert "if [[ -e /etc/igiris/igiris.env ]]" in installer
    assert "Existing Igris environment configuration retained." in installer


def test_packaging_defaults_to_explicit_localhost_bind_mode():
    installer = (ROOT / "packaging" / "install.sh").read_text()
    environment = (ROOT / "packaging" / "igiris.env").read_text()
    service = (ROOT / "packaging" / "igiris.service").read_text()

    assert "IGIRIS_BIND_MODE=localhost" in environment.splitlines()
    assert not any(
        line.startswith("IGIRIS_BIND_HOST=") for line in environment.splitlines()
    )
    assert "Environment=IGIRIS_BIND_MODE=localhost" in service.splitlines()
    assert "IGIRIS_BIND_MODE=network" in installer


def test_security_audit_runs_before_scanner_dependencies_are_installed():
    security = (ROOT / "tests" / "security.sh").read_text()
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text()

    assert "pip==26.2" in security
    assert "setuptools==83.0.0" in security
    assert "semgrep==1.172.0" in security
    assert "zizmor==1.28.0" in security
    assert security.index("python -m pip_audit --local") < security.index("semgrep==")
    assert "pip==26.2" in workflow
    assert "semgrep==1.172.0" in workflow
    assert "zizmor==1.28.0" in workflow
