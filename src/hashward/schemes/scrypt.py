"""Scrypt password hashing scheme handler (pure Python via hashlib)."""

from __future__ import annotations

import hashlib
import struct

from hashward._utils import ab64_decode, ab64_encode, consteq, generate_salt, to_bytes
from hashward.schemes._base import AbstractHandler


def _encode_scrypt_params(n: int, r: int, p: int) -> str:
    """Encode scrypt N/r/p parameters as a hex string (passlib $s0$ format)."""
    # log2(N) is stored in the high byte, r in the middle, p in the low byte
    ln = 0
    v = n
    while v > 1:
        v >>= 1
        ln += 1
    # Pack as 3 bytes: ln, r, p — then hex encode
    packed = struct.pack(">BHB", ln, r, p)
    return packed.hex()


def _decode_scrypt_params(params_hex: str) -> tuple[int, int, int]:
    """Decode scrypt parameters from hex string."""
    packed = bytes.fromhex(params_hex)
    ln, r, p = struct.unpack(">BHB", packed)
    n = 1 << ln
    return n, r, p


class ScryptHandler(AbstractHandler):
    """Scrypt password hashing via hashlib.scrypt.

    Hash format: $s0$params$b64salt$b64hash
    """

    SCHEME = "scrypt"

    _PREFIX = "$s0$"
    _DEFAULT_N = 16384  # CPU/memory cost
    _DEFAULT_R = 8  # Block size
    _DEFAULT_P = 1  # Parallelism
    _SALT_SIZE = 16
    _DKLEN = 32

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        n = settings.get("n", self._DEFAULT_N)
        r = settings.get("r", self._DEFAULT_R)
        p = settings.get("p", self._DEFAULT_P)
        salt = generate_salt(self._SALT_SIZE)

        dk = hashlib.scrypt(
            secret_bytes, salt=salt, n=n, r=r, p=p, dklen=self._DKLEN
        )

        params = _encode_scrypt_params(n, r, p)
        salt_str = ab64_encode(salt)
        hash_str = ab64_encode(dk)
        return f"{self._PREFIX}{params}${salt_str}${hash_str}"

    def verify(self, secret: str | bytes, hash: str) -> bool:
        if not hash.startswith(self._PREFIX):
            return False
        try:
            rest = hash[len(self._PREFIX):]
            parts = rest.split("$")
            if len(parts) != 3:
                return False
            n, r, p = _decode_scrypt_params(parts[0])
            salt = ab64_decode(parts[1])
            expected_hash = parts[2]
        except (ValueError, IndexError, struct.error):
            return False

        secret_bytes = to_bytes(secret)
        try:
            dk = hashlib.scrypt(
                secret_bytes, salt=salt, n=n, r=r, p=p, dklen=self._DKLEN
            )
        except ValueError:
            return False
        computed = ab64_encode(dk)
        return consteq(computed, expected_hash)

    def identify(self, hash: str) -> bool:
        return hash.startswith(self._PREFIX) or hash.startswith("$scrypt$")

    def needs_update(self, hash: str) -> bool:
        if not hash.startswith(self._PREFIX):
            return True
        try:
            rest = hash[len(self._PREFIX):]
            params_hex = rest.split("$")[0]
            n, r, p = _decode_scrypt_params(params_hex)
            return n < self._DEFAULT_N or r < self._DEFAULT_R or p < self._DEFAULT_P
        except (ValueError, IndexError, struct.error):
            return True
