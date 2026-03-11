"""Argon2 password hashing scheme handler."""

from __future__ import annotations

from hashward.exc import MissingBackendError
from hashward.schemes._base import AbstractHandler

try:
    import argon2
    from argon2 import PasswordHasher as _PasswordHasher
    from argon2.exceptions import (
        HashingError,
        InvalidHashError as _ArgonInvalidHash,
        VerificationError,
        VerifyMismatchError,
    )

    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False


def _ensure_backend() -> None:
    if not _HAS_ARGON2:
        raise MissingBackendError(
            "argon2-cffi is required for argon2 hashing. "
            "Install it with: pip install hashward[argon2]"
        )


class Argon2Handler(AbstractHandler):
    """Argon2 (id/i/d) password hashing via argon2-cffi."""

    SCHEME = "argon2"

    _PREFIXES = ("$argon2id$", "$argon2i$", "$argon2d$")

    # Default parameters (argon2id)
    _DEFAULT_TIME_COST = 2
    _DEFAULT_MEMORY_COST = 65536  # 64 MiB
    _DEFAULT_PARALLELISM = 2
    _DEFAULT_HASH_LEN = 32
    _DEFAULT_SALT_LEN = 16

    def hash(self, secret: str | bytes, **settings) -> str:
        _ensure_backend()
        # argon2-cffi accepts both str and bytes natively.
        time_cost = settings.get("time_cost", self._DEFAULT_TIME_COST)
        memory_cost = settings.get("memory_cost", self._DEFAULT_MEMORY_COST)
        parallelism = settings.get("parallelism", self._DEFAULT_PARALLELISM)
        hash_len = settings.get("hash_len", self._DEFAULT_HASH_LEN)
        salt_len = settings.get("salt_len", self._DEFAULT_SALT_LEN)

        ph = _PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=argon2.Type.ID,
        )
        return ph.hash(secret)

    def verify(self, secret: str | bytes, hash: str) -> bool:
        _ensure_backend()
        # argon2-cffi accepts both str and bytes natively.
        ph = _PasswordHasher()
        try:
            return ph.verify(hash, secret)
        except (VerifyMismatchError, VerificationError, _ArgonInvalidHash):
            return False

    def identify(self, hash: str) -> bool:
        return any(hash.startswith(p) for p in self._PREFIXES)

    def needs_update(self, hash: str) -> bool:
        _ensure_backend()
        ph = _PasswordHasher(
            time_cost=self._DEFAULT_TIME_COST,
            memory_cost=self._DEFAULT_MEMORY_COST,
            parallelism=self._DEFAULT_PARALLELISM,
            hash_len=self._DEFAULT_HASH_LEN,
        )
        try:
            return ph.check_needs_rehash(hash)
        except Exception:
            return True
