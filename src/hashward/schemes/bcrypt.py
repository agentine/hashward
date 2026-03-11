"""Bcrypt password hashing scheme handlers."""

from __future__ import annotations

import hashlib
import re

from hashward._utils import to_bytes
from hashward.exc import MissingBackendError
from hashward.schemes._base import AbstractHandler

try:
    import bcrypt as _bcrypt

    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False


def _ensure_backend() -> None:
    if not _HAS_BCRYPT:
        raise MissingBackendError(
            "bcrypt is required for bcrypt hashing. "
            "Install it with: pip install hashward[bcrypt]"
        )


_BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$.{53}$")
_DEFAULT_ROUNDS = 12


class BcryptHandler(AbstractHandler):
    """Standard bcrypt password hashing."""

    SCHEME = "bcrypt"

    def hash(self, secret: str | bytes, **settings) -> str:
        _ensure_backend()
        secret_bytes = to_bytes(secret)
        # bcrypt has a 72-byte limit on passwords
        secret_bytes = secret_bytes[:72]
        rounds = settings.get("rounds", _DEFAULT_ROUNDS)
        salt = _bcrypt.gensalt(rounds=rounds)
        return _bcrypt.hashpw(secret_bytes, salt).decode("ascii")

    def verify(self, secret: str | bytes, hash: str) -> bool:
        _ensure_backend()
        secret_bytes = to_bytes(secret)
        secret_bytes = secret_bytes[:72]
        try:
            return _bcrypt.checkpw(secret_bytes, hash.encode("ascii"))
        except (ValueError, TypeError):
            return False

    def identify(self, hash: str) -> bool:
        return bool(_BCRYPT_RE.match(hash))

    def needs_update(self, hash: str) -> bool:
        try:
            # Extract rounds from $2b$XX$...
            rounds = int(hash.split("$")[2])
            return rounds < _DEFAULT_ROUNDS
        except (IndexError, ValueError):
            return True


class BcryptSha256Handler(AbstractHandler):
    """Bcrypt with SHA-256 pre-hashing (passlib-compatible).

    Wraps the password in SHA-256 before passing to bcrypt, avoiding
    the 72-byte password length limit.
    """

    SCHEME = "bcrypt_sha256"

    _PREFIX = "$bcrypt-sha256$"

    def hash(self, secret: str | bytes, **settings) -> str:
        _ensure_backend()
        secret_bytes = to_bytes(secret)
        # SHA-256 the password first to avoid 72-byte limit
        sha_digest = hashlib.sha256(secret_bytes).hexdigest()
        rounds = settings.get("rounds", _DEFAULT_ROUNDS)
        salt = _bcrypt.gensalt(rounds=rounds)
        bcrypt_hash = _bcrypt.hashpw(sha_digest.encode("ascii"), salt).decode("ascii")
        return f"{self._PREFIX}{bcrypt_hash}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        _ensure_backend()
        if not hash.startswith(self._PREFIX):
            return False
        secret_bytes = to_bytes(secret)
        sha_digest = hashlib.sha256(secret_bytes).hexdigest()
        bcrypt_hash = hash[len(self._PREFIX):]
        try:
            return _bcrypt.checkpw(
                sha_digest.encode("ascii"), bcrypt_hash.encode("ascii")
            )
        except (ValueError, TypeError):
            return False

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            bcrypt_part = hash[len(self._PREFIX):]
            rounds = int(bcrypt_part.split("$")[2])
            return rounds < _DEFAULT_ROUNDS
        except (IndexError, ValueError):
            return True
