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

# Passlib bcrypt_sha256 format regexes
_PASSLIB_V1_RE = re.compile(
    r"^\$bcrypt-sha256\$(2[ab]?),(\d+),([A-Za-z0-9./]{22})\$([A-Za-z0-9./]{31})$"
)
_PASSLIB_V2_RE = re.compile(
    r"^\$bcrypt-sha256\$v=2,t=(2[ab]?),r=(\d+)\$([A-Za-z0-9./]{22})\$([A-Za-z0-9./]{31})$"
)


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

        bcrypt_hash = self._extract_bcrypt_hash(hash)
        if bcrypt_hash is None:
            return False

        try:
            return _bcrypt.checkpw(
                sha_digest.encode("ascii"), bcrypt_hash.encode("ascii")
            )
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _extract_bcrypt_hash(hash: str) -> str | None:
        """Extract a standard bcrypt hash from any supported format.

        Supports:
        - hashward native: $bcrypt-sha256$$2b$12$<salt><hash>
        - passlib v1: $bcrypt-sha256$2a,12,<salt22>$<hash31>
        - passlib v2: $bcrypt-sha256$v=2,t=2b,r=12$<salt22>$<hash31>
        """
        # Try passlib v2 first (more specific prefix)
        m = _PASSLIB_V2_RE.match(hash)
        if m:
            ident, rounds, salt64, checksum64 = m.groups()
            return f"${ident}${rounds}${salt64}{checksum64}"

        # Try passlib v1
        m = _PASSLIB_V1_RE.match(hash)
        if m:
            ident, rounds, salt64, checksum64 = m.groups()
            return f"${ident}${rounds}${salt64}{checksum64}"

        # hashward native: prefix followed by full bcrypt hash
        rest = hash[len(BcryptSha256Handler._PREFIX):]
        if _BCRYPT_RE.match(rest):
            return rest

        return None

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            bcrypt_part = self._extract_bcrypt_hash(hash)
            if bcrypt_part is None:
                return True
            rounds = int(bcrypt_part.split("$")[2])
            return rounds < _DEFAULT_ROUNDS
        except (IndexError, ValueError):
            return True
