from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from igris.auth import (
    LoginLimiter,
    SessionManager,
    hash_password,
    read_password_verifier,
    verify_password,
    write_password_verifier,
)


def test_password_scrypt_work_factor_meets_current_minimum():
    verifier = hash_password("test password", salt=b"0123456789abcdef")

    assert int(verifier.split("$")[2]) >= 1 << 17


def test_password_verifier_is_salted_and_rejects_wrong_password():
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first != second
    assert "correct horse battery staple" not in first
    assert verify_password("correct horse battery staple", first) is True
    assert verify_password("wrong password", first) is False


@pytest.mark.parametrize("mutate", [
    lambda fields: fields.__setitem__(2, str((1 << 14) * 2)),
    lambda fields: fields.__setitem__(3, "08"),
    lambda fields: fields.__setitem__(4, "2"),
    lambda fields: fields.__setitem__(5, "A" * 21),
    lambda fields: fields.__setitem__(5, "A" * 23),
    lambda fields: fields.__setitem__(6, "A" * 42),
    lambda fields: fields.__setitem__(6, "A" * 44),
    lambda fields: fields.__setitem__(6, "A" * 100_000),
])
def test_password_verifier_rejects_noncanonical_or_unbounded_fields_before_scrypt(monkeypatch, mutate):
    fields = hash_password("test password", salt=b"0123456789abcdef").split("$")
    mutate(fields)
    monkeypatch.setattr("igris.auth.hashlib.scrypt", lambda *args, **kwargs: pytest.fail("scrypt called"))

    assert verify_password("test password", "$".join(fields)) is False


def test_password_verifier_file_is_owner_only_and_contains_no_plaintext(tmp_path):
    path = tmp_path / "password.verifier"

    write_password_verifier(path, "a private local password")

    assert path.stat().st_mode & 0o777 == 0o600
    assert "a private local password" not in path.read_text()
    assert verify_password("a private local password", read_password_verifier(path)) is True


def test_password_verifier_reader_rejects_symlinks_nonregular_files_and_wrong_owner(tmp_path):
    path = tmp_path / "password.verifier"
    write_password_verifier(path, "a private local password")
    link = tmp_path / "password-link"
    link.symlink_to(path)

    with pytest.raises(ValueError, match="regular file"):
        read_password_verifier(link)
    with pytest.raises(ValueError, match="regular file"):
        read_password_verifier(tmp_path)
    with pytest.raises(ValueError, match="owned by the service user"):
        read_password_verifier(path, expected_uid=path.stat().st_uid + 1)


def test_session_tokens_expire_and_can_be_revoked():
    now = [100.0]
    sessions = SessionManager(ttl_seconds=60, clock=lambda: now[0])

    token = sessions.issue()

    assert len(token) >= 32
    assert sessions.authenticate(token) is True
    now[0] = 161.0
    assert sessions.authenticate(token) is False

    fresh = sessions.issue()
    assert sessions.authenticate(fresh) is True
    sessions.revoke(fresh)
    assert sessions.authenticate(fresh) is False


def test_session_revoke_waits_for_in_progress_authentication_mutation():
    sessions = SessionManager(ttl_seconds=60, clock=lambda: 100.0)
    token = sessions.issue()
    authentication_started = threading.Event()
    release_authentication = threading.Event()
    revoke_finished = threading.Event()

    def blocking_clock():
        authentication_started.set()
        release_authentication.wait(timeout=2)
        return 100.0

    sessions.clock = blocking_clock
    auth_thread = threading.Thread(target=sessions.authenticate, args=(token,))
    auth_thread.start()
    assert authentication_started.wait(timeout=1)

    revoke_thread = threading.Thread(target=lambda: (sessions.revoke(token), revoke_finished.set()))
    revoke_thread.start()
    assert revoke_finished.wait(timeout=0.1) is False
    release_authentication.set()
    auth_thread.join(timeout=1)
    revoke_thread.join(timeout=1)

    assert revoke_finished.is_set()
    assert sessions.authenticate(token) is False


def test_login_limiter_blocks_repeated_failures_until_window_expires():
    now = [100.0]
    limiter = LoginLimiter(max_failures=3, window_seconds=60, clock=lambda: now[0])

    for _ in range(3):
        assert limiter.allowed("192.0.2.10") is True
        limiter.record_failure("192.0.2.10")

    assert limiter.allowed("192.0.2.10") is False
    assert limiter.allowed("192.0.2.11") is True
    now[0] = 161.0
    assert limiter.allowed("192.0.2.10") is True

    limiter.record_failure("192.0.2.10")
    limiter.clear("192.0.2.10")
    assert limiter.allowed("192.0.2.10") is True


def test_login_limiter_bounds_tracked_clients_and_fails_closed_at_capacity():
    limiter = LoginLimiter(max_failures=3, window_seconds=60, max_clients=2, clock=lambda: 100.0)

    assert limiter.reserve("192.0.2.1") is None
    assert limiter.reserve("192.0.2.2") is None
    assert limiter.reserve("192.0.2.3") == 60
    assert limiter.active_client_count == 2


def test_login_limiter_atomically_reserves_only_bounded_parallel_attempts():
    limiter = LoginLimiter(max_failures=3, window_seconds=60, clock=lambda: 100.0)
    barrier = threading.Barrier(12)

    def reserve():
        barrier.wait()
        return limiter.reserve("192.0.2.10")

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: reserve(), range(12)))

    assert results.count(None) == 3
    assert all(retry == 60 for retry in results if retry is not None)
