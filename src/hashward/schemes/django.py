"""Django-compatible password hasher handlers.

Supports Django's hash format for PBKDF2-SHA256, bcrypt, argon2, and scrypt.
"""

from __future__ import annotations

import base64
import hashlib
import os

from hashward._utils import consteq, to_bytes
from hashward.schemes._base import AbstractHandler


class DjangoPbkdf2Sha256Handler(AbstractHandler):
    """Django PBKDF2-SHA256 password hashing.

    Hash format: pbkdf2_sha256$iterations$salt$hash
    """

    SCHEME = "django_pbkdf2_sha256"
    _PREFIX = "pbkdf2_sha256$"
    _DEFAULT_ITERATIONS = 600000
    _DKLEN = 32

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        iterations = settings.get("iterations", self._DEFAULT_ITERATIONS)
        salt = settings.get("salt", base64.b64encode(os.urandom(12)).decode("ascii"))

        dk = hashlib.pbkdf2_hmac("sha256", secret_bytes, salt.encode("ascii"), iterations, dklen=self._DKLEN)
        hash_b64 = base64.b64encode(dk).decode("ascii")
        return f"pbkdf2_sha256${iterations}${salt}${hash_b64}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        try:
            parts = hash.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            expected = parts[3]
        except (ValueError, IndexError):
            return False

        secret_bytes = to_bytes(secret)
        dk = hashlib.pbkdf2_hmac("sha256", secret_bytes, salt.encode("ascii"), iterations, dklen=self._DKLEN)
        computed = base64.b64encode(dk).decode("ascii")
        return consteq(computed, expected)

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            parts = hash.split("$")
            iterations = int(parts[1])
            return iterations < self._DEFAULT_ITERATIONS
        except (ValueError, IndexError):
            return True


class DjangoBcryptHandler(AbstractHandler):
    """Django bcrypt password hashing.

    Hash format: bcrypt$$2b$...
    """

    SCHEME = "django_bcrypt"
    _PREFIX = "bcrypt$"
    _DEFAULT_ROUNDS = 12

    def _ensure_backend(self) -> None:
        try:
            import bcrypt as _bcrypt  # noqa: F401
        except ImportError:
            from hashward.exc import MissingBackendError
            raise MissingBackendError("bcrypt library is required: pip install bcrypt")

    def hash(self, secret: str | bytes, **settings) -> str:
        self._ensure_backend()
        import bcrypt

        secret_bytes = to_bytes(secret)[:72]
        rounds = settings.get("rounds", self._DEFAULT_ROUNDS)
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(secret_bytes, salt)
        return f"bcrypt${hashed.decode('ascii')}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        self._ensure_backend()
        import bcrypt

        secret_bytes = to_bytes(secret)[:72]
        bcrypt_hash = hash[len(self._PREFIX):].encode("ascii")
        try:
            return bcrypt.checkpw(secret_bytes, bcrypt_hash)
        except (ValueError, TypeError):
            return False

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX) and not hash.startswith("bcrypt_sha256$")

    def needs_update(self, hash: str) -> bool:
        try:
            bcrypt_part = hash[len(self._PREFIX):]
            # Extract rounds from $2b$XX$...
            rounds = int(bcrypt_part.split("$")[2])
            return rounds < self._DEFAULT_ROUNDS
        except (ValueError, IndexError):
            return True


class DjangoBcryptSha256Handler(AbstractHandler):
    """Django bcrypt_sha256 password hashing.

    Hash format: bcrypt_sha256$$2b$...
    Pre-hashes the password with SHA-256 before bcrypt (like passlib).
    """

    SCHEME = "django_bcrypt_sha256"
    _PREFIX = "bcrypt_sha256$"
    _DEFAULT_ROUNDS = 12

    def _ensure_backend(self) -> None:
        try:
            import bcrypt as _bcrypt  # noqa: F401
        except ImportError:
            from hashward.exc import MissingBackendError
            raise MissingBackendError("bcrypt library is required: pip install bcrypt")

    def hash(self, secret: str | bytes, **settings) -> str:
        self._ensure_backend()
        import bcrypt

        secret_bytes = to_bytes(secret)
        sha_digest = hashlib.sha256(secret_bytes).hexdigest()
        rounds = settings.get("rounds", self._DEFAULT_ROUNDS)
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(sha_digest.encode("ascii"), salt)
        return f"bcrypt_sha256${hashed.decode('ascii')}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        self._ensure_backend()
        import bcrypt

        secret_bytes = to_bytes(secret)
        sha_digest = hashlib.sha256(secret_bytes).hexdigest()
        bcrypt_hash = hash[len(self._PREFIX):].encode("ascii")
        try:
            return bcrypt.checkpw(sha_digest.encode("ascii"), bcrypt_hash)
        except (ValueError, TypeError):
            return False

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            bcrypt_part = hash[len(self._PREFIX):]
            rounds = int(bcrypt_part.split("$")[2])
            return rounds < self._DEFAULT_ROUNDS
        except (ValueError, IndexError):
            return True


class DjangoArgon2Handler(AbstractHandler):
    """Django argon2 password hashing.

    Hash format: argon2$argon2id$...
    """

    SCHEME = "django_argon2"
    _PREFIX = "argon2$"

    def _ensure_backend(self) -> None:
        try:
            import argon2 as _argon2  # noqa: F401
        except ImportError:
            from hashward.exc import MissingBackendError
            raise MissingBackendError("argon2-cffi library is required: pip install argon2-cffi")

    def hash(self, secret: str | bytes, **settings) -> str:
        self._ensure_backend()
        from argon2 import PasswordHasher

        ph = PasswordHasher(
            time_cost=settings.get("time_cost", 2),
            memory_cost=settings.get("memory_cost", 102400),
            parallelism=settings.get("parallelism", 8),
        )
        secret_bytes = to_bytes(secret)
        argon2_hash = ph.hash(secret_bytes)
        return f"argon2${argon2_hash}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        self._ensure_backend()
        from argon2 import PasswordHasher
        from argon2.exceptions import (
            InvalidHashError as _ArgonInvalidHash,
            VerifyMismatchError,
            VerificationError,
        )

        ph = PasswordHasher()
        argon2_hash = hash[len(self._PREFIX):]
        secret_bytes = to_bytes(secret)
        try:
            return ph.verify(argon2_hash, secret_bytes)
        except (VerifyMismatchError, VerificationError, _ArgonInvalidHash):
            return False

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        self._ensure_backend()
        from argon2 import PasswordHasher

        argon2_hash = hash[len(self._PREFIX):]
        ph = PasswordHasher(
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
        )
        try:
            return ph.check_needs_rehash(argon2_hash)
        except Exception:
            return True


class DjangoScryptHandler(AbstractHandler):
    """Django scrypt password hashing.

    Hash format: scrypt$salt$N$r$p$hash
    """

    SCHEME = "django_scrypt"
    _PREFIX = "scrypt$"
    _DEFAULT_N = 2**14
    _DEFAULT_R = 8
    _DEFAULT_P = 1

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        n = settings.get("n", self._DEFAULT_N)
        r = settings.get("r", self._DEFAULT_R)
        p = settings.get("p", self._DEFAULT_P)
        salt = settings.get("salt", base64.b64encode(os.urandom(16)).decode("ascii"))

        dk = hashlib.scrypt(secret_bytes, salt=salt.encode("ascii"), n=n, r=r, p=p, dklen=64)
        hash_b64 = base64.b64encode(dk).decode("ascii")
        return f"scrypt${salt}${n}${r}${p}${hash_b64}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        try:
            parts = hash.split("$")
            # scrypt$salt$N$r$p$hash
            if len(parts) != 6:
                return False
            salt = parts[1]
            n = int(parts[2])
            r = int(parts[3])
            p = int(parts[4])
            expected = parts[5]
        except (ValueError, IndexError):
            return False

        secret_bytes = to_bytes(secret)
        try:
            dk = hashlib.scrypt(secret_bytes, salt=salt.encode("ascii"), n=n, r=r, p=p, dklen=64)
        except ValueError:
            return False
        computed = base64.b64encode(dk).decode("ascii")
        return consteq(computed, expected)

    def identify(self, hash: str) -> bool:
        # Must not match hashward's native $scrypt$ format
        if hash.startswith("$scrypt$"):
            return False
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            parts = hash.split("$")
            n = int(parts[2])
            return n < self._DEFAULT_N
        except (ValueError, IndexError):
            return True
