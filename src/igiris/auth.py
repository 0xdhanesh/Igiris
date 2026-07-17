from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from pathlib import Path


SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 256 * 1024 * 1024


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("Password must not be empty")
    salt = salt or os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return f"scrypt$v1${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_encode(salt)}${_encode(derived)}"


def verify_password(password: str, verifier: str) -> bool:
    try:
        algorithm, version, raw_n, raw_r, raw_p, raw_salt, raw_expected = verifier.split("$")
        if (
            algorithm != "scrypt"
            or version != "v1"
            or (raw_n, raw_r, raw_p) != (str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P))
            or len(raw_salt) != 22
            or len(raw_expected) != 43
            or not re.fullmatch(r"[A-Za-z0-9_-]+", raw_salt)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", raw_expected)
        ):
            return False
        salt = _decode(raw_salt)
        expected = _decode(raw_expected)
        if len(salt) != 16 or len(expected) != SCRYPT_DKLEN or _encode(salt) != raw_salt or _encode(expected) != raw_expected:
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )
    except (TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(derived, expected)


def write_password_verifier(path: str | Path, password: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    verifier = hash_password(password)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(verifier + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        destination.chmod(0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_password_verifier(path: str | Path, *, expected_uid: int | None = None) -> str:
    source = Path(path)
    expected_uid = os.geteuid() if expected_uid is None else expected_uid
    try:
        fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("Password verifier must be a regular file, not a symlink") from error
        raise
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Password verifier must be a regular file")
        if metadata.st_uid != expected_uid:
            raise ValueError("Password verifier file must be owned by the service user")
        if metadata.st_mode & 0o077:
            raise ValueError("Password verifier file must be owner-only (0600)")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            verifier = stream.read().strip()
    finally:
        if fd >= 0:
            os.close(fd)
    if not verifier:
        raise ValueError("Password verifier file is empty")
    return verifier


class LoginLimiter:
    def __init__(self, max_failures: int = 5, window_seconds: int = 60, max_clients: int = 4096, clock=time.monotonic):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self.clock = clock
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, client: str) -> list[float]:
        cutoff = self.clock() - self.window_seconds
        recent = [observed for observed in self._failures.get(client, []) if observed > cutoff]
        if recent:
            self._failures[client] = recent
        else:
            self._failures.pop(client, None)
        return recent

    def _prune_all(self) -> None:
        for client in list(self._failures):
            self._recent(client)

    @property
    def active_client_count(self) -> int:
        with self._lock:
            self._prune_all()
            return len(self._failures)

    def allowed(self, client: str) -> bool:
        with self._lock:
            return len(self._recent(client)) < self.max_failures

    def record_failure(self, client: str) -> None:
        with self._lock:
            recent = self._recent(client)
            recent.append(self.clock())
            self._failures[client] = recent

    def reserve(self, client: str) -> int | None:
        """Reserve one password-check slot, or return seconds until one is available."""
        with self._lock:
            self._prune_all()
            now = self.clock()
            if client not in self._failures and len(self._failures) >= self.max_clients:
                earliest = min(observed[0] for observed in self._failures.values())
                return max(1, int(earliest + self.window_seconds - now + 0.999999))
            recent = self._recent(client)
            if len(recent) >= self.max_failures:
                return max(1, int(recent[0] + self.window_seconds - now + 0.999999))
            recent.append(now)
            self._failures[client] = recent
            return None

    def clear(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


class SessionManager:
    def __init__(self, ttl_seconds: int = 8 * 60 * 60, clock=time.monotonic):
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _purge(self) -> None:
        now = self.clock()
        self._sessions = {digest: expiry for digest, expiry in self._sessions.items() if expiry > now}

    def issue(self) -> str:
        with self._lock:
            self._purge()
            token = secrets.token_urlsafe(32)
            self._sessions[self._digest(token)] = self.clock() + self.ttl_seconds
            return token

    def authenticate(self, token: str) -> bool:
        if not token or not token.isascii():
            return False
        with self._lock:
            self._purge()
            return self._sessions.get(self._digest(token), 0) > self.clock()

    def revoke(self, token: str) -> None:
        if token and token.isascii():
            with self._lock:
                self._sessions.pop(self._digest(token), None)
