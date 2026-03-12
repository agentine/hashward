"""MD5-crypt password hashing (pure Python).

Implements the FreeBSD MD5-crypt algorithm.
Hash format: $1$salt$hash

No stdlib crypt dependency — works on Python 3.13+.
"""

from __future__ import annotations

import hashlib

from hashward._utils import consteq, to_bytes
from hashward.schemes._base import AbstractHandler
from hashward.schemes.sha_crypt import _SALT_CHARS, _generate_salt, _validate_salt


def _hash64_encode_md5(data: bytes) -> str:
    """Encode 16 bytes of MD5 digest to the md5-crypt base64 format (22 chars)."""
    itoa64 = _SALT_CHARS
    out: list[str] = []

    # MD5 encoding order (groups of 3 bytes -> 4 chars each)
    order = [
        (0, 6, 12), (1, 7, 13), (2, 8, 14),
        (3, 9, 15), (4, 10, 5),
    ]
    for a, b, c in order:
        v = (data[a] << 16) | (data[b] << 8) | data[c]
        for _ in range(4):
            out.append(itoa64[v & 0x3F])
            v >>= 6

    # Final byte (index 11) -> 2 chars
    v = data[11]
    for _ in range(2):
        out.append(itoa64[v & 0x3F])
        v >>= 6

    return "".join(out)


def _md5_crypt(secret: bytes, salt: str) -> str:
    """Compute MD5-crypt hash per the FreeBSD spec."""
    prefix = b"$1$"
    salt_bytes = salt.encode("ascii")

    # Start digest A
    a_ctx = hashlib.md5(secret + prefix + salt_bytes)

    # Digest B
    b = hashlib.md5(secret + salt_bytes + secret).digest()

    # Add bytes from B to A
    secret_len = len(secret)
    remaining = secret_len
    while remaining > 16:
        a_ctx.update(b)
        remaining -= 16
    a_ctx.update(b[:remaining])

    # Process secret length bits
    n = secret_len
    while n > 0:
        if n & 1:
            a_ctx.update(b"\x00")
        else:
            a_ctx.update(secret[:1])
        n >>= 1

    a = a_ctx.digest()

    # 1000 rounds
    for i in range(1000):
        ctx = hashlib.md5()
        if i & 1:
            ctx.update(secret)
        else:
            ctx.update(a)
        if i % 3:
            ctx.update(salt_bytes)
        if i % 7:
            ctx.update(secret)
        if i & 1:
            ctx.update(a)
        else:
            ctx.update(secret)
        a = ctx.digest()

    encoded = _hash64_encode_md5(a)
    return f"$1${salt}${encoded}"


class Md5CryptHandler(AbstractHandler):
    """MD5-crypt password hashing ($1$). Deprecated — always needs_update."""

    SCHEME = "md5_crypt"
    _PREFIX = "$1$"

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        salt = settings.get("salt", _generate_salt(8))
        salt = _validate_salt(salt, 8)
        return _md5_crypt(secret_bytes, salt)

    def _verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        try:
            parts = hash.split("$")
            # $1$salt$hash -> ['', '1', 'salt', 'hash']
            if len(parts) != 4:
                return False
            salt = parts[2]
        except (ValueError, IndexError):
            return False
        secret_bytes = to_bytes(secret)
        computed = _md5_crypt(secret_bytes, salt)
        return consteq(computed, hash)

    def _identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX)

    def needs_update(self, hash: str) -> bool:
        return True  # MD5-crypt is deprecated
