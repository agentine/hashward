"""SHA-256-crypt and SHA-512-crypt password hashing (pure Python).

Implements the algorithm specified at:
https://www.akkadia.org/drepper/SHA-crypt.txt

No stdlib crypt dependency — works on Python 3.13+.
"""

from __future__ import annotations

import hashlib
import os
import re

from hashward._utils import consteq, to_bytes
from hashward.schemes._base import AbstractHandler

# Salt alphabet: [a-zA-Z0-9./]
_SALT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_ROUNDS_MIN = 1000
_ROUNDS_MAX = 999_999_999

_SALT_CHARS_SET = frozenset(_SALT_CHARS)


def _validate_salt(salt: str, max_len: int) -> str:
    """Validate and truncate a salt string.

    Ensures all characters are in the allowed alphabet and truncates
    to the maximum length for the scheme.
    """
    salt = salt[:max_len]
    for ch in salt:
        if ch not in _SALT_CHARS_SET:
            raise ValueError(
                f"Invalid salt character: {ch!r}. "
                f"Salt must contain only characters from: {_SALT_CHARS}"
            )
    return salt


def _generate_salt(size: int = 16) -> str:
    """Generate a random salt string from the allowed alphabet."""
    raw = os.urandom(size)
    return "".join(_SALT_CHARS[b % len(_SALT_CHARS)] for b in raw)


def _hash64_encode(data: bytes, order: list[tuple[int, int, int]], final_bytes: tuple[list[int], int] | None = None) -> str:
    """Encode hash bytes to the custom base64 used by sha-crypt/md5-crypt."""
    itoa64 = _SALT_CHARS
    out: list[str] = []
    for a, b, c in order:
        v = (data[a] << 16) | (data[b] << 8) | data[c]
        for _ in range(4):
            out.append(itoa64[v & 0x3F])
            v >>= 6
    if final_bytes is not None:
        indices, n_chars = final_bytes
        v = 0
        for i, idx in enumerate(indices):
            v |= data[idx] << (8 * i)
        for _ in range(n_chars):
            out.append(itoa64[v & 0x3F])
            v >>= 6
    return "".join(out)


# SHA-512 encoding order (from the spec)
_SHA512_ORDER = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23),
    (3, 24, 45), (25, 46, 4), (47, 5, 26),
    (6, 27, 48), (28, 49, 7), (50, 8, 29),
    (9, 30, 51), (31, 52, 10), (53, 11, 32),
    (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38),
    (18, 39, 60), (40, 61, 19), (62, 20, 41),
]

# SHA-256 encoding order (from the spec)
_SHA256_ORDER = [
    (0, 10, 20), (21, 1, 11), (12, 22, 2),
    (3, 13, 23), (24, 4, 14), (15, 25, 5),
    (6, 16, 26), (27, 7, 17), (18, 28, 8),
    (9, 19, 29),
]


def _sha_crypt(secret: bytes, salt: str, rounds: int, hash_func: str) -> str:
    """Core SHA-crypt algorithm shared by SHA-256 and SHA-512."""
    if hash_func == "sha256":
        new_hash = hashlib.sha256
        prefix = "$5$"
        digest_size = 32
        order = _SHA256_ORDER
        final_bytes = ([30, 31], 3)  # bytes 30+31 → 3 chars
    else:
        new_hash = hashlib.sha512
        prefix = "$6$"
        digest_size = 64
        order = _SHA512_ORDER
        final_bytes = ([63], 2)  # byte 63 → 2 chars

    salt_bytes = salt.encode("ascii")

    # Step 1-3: Digest B
    b = new_hash(secret + salt_bytes + secret).digest()

    # Step 4-8: Digest A
    a_ctx = new_hash(secret + salt_bytes)
    # Step 9-10: Add bytes from B
    secret_len = len(secret)
    remaining = secret_len
    while remaining > digest_size:
        a_ctx.update(b)
        remaining -= digest_size
    a_ctx.update(b[:remaining])

    # Step 11: Process secret length bits
    n = secret_len
    while n > 0:
        if n & 1:
            a_ctx.update(b)
        else:
            a_ctx.update(secret)
        n >>= 1

    a = a_ctx.digest()

    # Step 12-13: Digest DP (key-derived)
    dp_ctx = new_hash()
    for _ in range(secret_len):
        dp_ctx.update(secret)
    dp = dp_ctx.digest()

    # Step 14: Produce P string
    p = b""
    remaining = secret_len
    while remaining > digest_size:
        p += dp
        remaining -= digest_size
    p += dp[:remaining]

    # Step 15-16: Digest DS (salt-derived)
    ds_ctx = new_hash()
    for _ in range(16 + a[0]):
        ds_ctx.update(salt_bytes)
    ds = ds_ctx.digest()

    # Step 17: Produce S string
    s = b""
    remaining = len(salt_bytes)
    while remaining > digest_size:
        s += ds
        remaining -= digest_size
    s += ds[:remaining]

    # Step 18-20: Rounds
    c = a
    for i in range(rounds):
        ctx = new_hash()
        if i & 1:
            ctx.update(p)
        else:
            ctx.update(c)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        if i & 1:
            ctx.update(c)
        else:
            ctx.update(p)
        c = ctx.digest()

    # Step 21: Encode
    encoded = _hash64_encode(c, order, final_bytes)

    # Build output
    if rounds == 5000:
        return f"{prefix}{salt}${encoded}"
    return f"{prefix}rounds={rounds}${salt}${encoded}"


class _ShaCryptHandler(AbstractHandler):
    """Base class for SHA-crypt handlers."""

    SCHEME = ""
    _PREFIX = ""
    _HASH_FUNC = ""
    _DEFAULT_ROUNDS = 0
    _MIN_ROUNDS = 100000
    _RE = re.compile(r"")

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        rounds = settings.get("rounds", self._DEFAULT_ROUNDS)
        rounds = max(_ROUNDS_MIN, min(_ROUNDS_MAX, rounds))
        salt = settings.get("salt", _generate_salt(16))
        salt = _validate_salt(salt, 16)
        return _sha_crypt(secret_bytes, salt, rounds, self._HASH_FUNC)

    def _verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        try:
            salt, rounds = self._parse(hash)
        except (ValueError, IndexError):
            return False
        secret_bytes = to_bytes(secret)
        computed = _sha_crypt(secret_bytes, salt, rounds, self._HASH_FUNC)
        return consteq(computed, hash)

    def _identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        try:
            _, rounds = self._parse(hash)
            return rounds < self._MIN_ROUNDS
        except (ValueError, IndexError):
            return True

    def _parse(self, hash: str) -> tuple[str, int]:
        """Parse a sha-crypt hash string, returning (salt, rounds)."""
        rest = hash[len(self._PREFIX):]
        if rest.startswith("rounds="):
            # $5$rounds=N$salt$hash
            parts = rest.split("$")
            rounds = int(parts[0].split("=")[1])
            salt = parts[1]
        else:
            # $5$salt$hash (implicit 5000 rounds)
            parts = rest.split("$")
            salt = parts[0]
            rounds = 5000
        return salt, rounds


class Sha256CryptHandler(_ShaCryptHandler):
    """SHA-256-crypt password hashing ($5$)."""

    SCHEME = "sha256_crypt"
    _PREFIX = "$5$"
    _HASH_FUNC = "sha256"
    _DEFAULT_ROUNDS = 535000
    _MIN_ROUNDS = 100000


class Sha512CryptHandler(_ShaCryptHandler):
    """SHA-512-crypt password hashing ($6$)."""

    SCHEME = "sha512_crypt"
    _PREFIX = "$6$"
    _HASH_FUNC = "sha512"
    _DEFAULT_ROUNDS = 656000
    _MIN_ROUNDS = 100000
