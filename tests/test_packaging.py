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
