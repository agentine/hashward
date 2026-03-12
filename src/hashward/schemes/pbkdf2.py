"""PBKDF2 password hashing scheme handlers (pure Python via hashlib)."""

from __future__ import annotations

import hashlib

from hashward._utils import ab64_decode, ab64_encode, consteq, generate_salt, to_bytes
from hashward.schemes._base import AbstractHandler


class _Pbkdf2Handler(AbstractHandler):
    """Base class for PBKDF2 handlers."""

    SCHEME = ""
    _HASH_FUNC = ""
    _PREFIX = ""
    _DEFAULT_ROUNDS = 0
    _SALT_SIZE = 16
    _DKLEN = 32

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        rounds = settings.get("rounds", self._DEFAULT_ROUNDS)
        salt = generate_salt(self._SALT_SIZE)
        salt_str = ab64_encode(salt)

        dk = hashlib.pbkdf2_hmac(
            self._HASH_FUNC,
            secret_bytes,
            salt,
            rounds,
            dklen=self._DKLEN,
        )
        hash_str = ab64_encode(dk)
        return f"{self._PREFIX}{rounds}${salt_str}${hash_str}"

    def _verify(self, secret: str | bytes, hash: str) -> bool:
        if not hash.startswith(self._PREFIX):
            return False
        try:
            rest = hash[len(self._PREFIX):]
            parts = rest.split("$")
            if len(parts) != 3:
                return False
            rounds = int(parts[0])
            salt = ab64_decode(parts[1])
            expected_hash = parts[2]
        except (ValueError, IndexError):
            return False

        secret_bytes = to_bytes(secret)
        dk = hashlib.pbkdf2_hmac(
            self._HASH_FUNC,
            secret_bytes,
            salt,
            rounds,
            dklen=self._DKLEN,
        )
        computed = ab64_encode(dk)
        return consteq(computed, expected_hash)

    def _identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            rest = hash[len(self._PREFIX):]
            rounds = int(rest.split("$")[0])
            return rounds < self._DEFAULT_ROUNDS
        except (ValueError, IndexError):
            return True


class Pbkdf2Sha256Handler(_Pbkdf2Handler):
    """PBKDF2-SHA256 password hashing."""

    SCHEME = "pbkdf2_sha256"
    _HASH_FUNC = "sha256"
    _PREFIX = "$pbkdf2-sha256$"
    _DEFAULT_ROUNDS = 600000
    _DKLEN = 32


class Pbkdf2Sha512Handler(_Pbkdf2Handler):
    """PBKDF2-SHA512 password hashing."""

    SCHEME = "pbkdf2_sha512"
    _HASH_FUNC = "sha512"
    _PREFIX = "$pbkdf2-sha512$"
    _DEFAULT_ROUNDS = 260000
    _DKLEN = 64
