import pytest

from igiris.auth import read_password_verifier, verify_password
from igiris.auth_cli import configure_password


def test_configure_password_prompts_twice_and_writes_verifier(tmp_path):
    answers = iter(["a sufficiently long password", "a sufficiently long password"])
    path = tmp_path / "password.verifier"

    configure_password(path, prompt=lambda _: next(answers))

    assert verify_password("a sufficiently long password", read_password_verifier(path)) is True


def test_configure_password_rejects_mismatch_without_writing(tmp_path):
    answers = iter(["a sufficiently long password", "a different long password"])
    path = tmp_path / "password.verifier"

    with pytest.raises(ValueError, match="do not match"):
        configure_password(path, prompt=lambda _: next(answers))

    assert not path.exists()


def test_configure_password_rejects_short_password(tmp_path):
    path = tmp_path / "password.verifier"

    with pytest.raises(ValueError, match="at least 12"):
        configure_password(path, prompt=lambda _: "too short")

    assert not path.exists()
