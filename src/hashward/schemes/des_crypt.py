"""Traditional DES-crypt password hashing (pure Python).

Hash format: 2-char salt + 11-char hash (13 chars total).
Disabled by default — not registered in DEFAULT_REGISTRY.

No stdlib crypt dependency — works on Python 3.13+.
"""

from __future__ import annotations

import os
import re

from hashward._utils import consteq, to_bytes
from hashward.schemes._base import AbstractHandler
from hashward.schemes.sha_crypt import _validate_salt

_SALT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_DES_HASH_RE = re.compile(r"^[./0-9A-Za-z]{13}$")

# DES tables
_IP = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
]

_FP = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
]

_PC1 = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
]

_PC2 = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
]

_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_E = [
    31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
]

_SBOXES = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]

_P = [
    15, 6, 19, 20, 28, 11, 27, 16,
    0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8,
    18, 12, 29, 5, 21, 10, 3, 24,
]


def _permute(block: int, table: list[int], n_bits: int) -> int:
    """Apply a permutation table to a bit block."""
    result = 0
    for i, pos in enumerate(table):
        if block & (1 << (n_bits - 1 - pos)):
            result |= 1 << (len(table) - 1 - i)
    return result


def _make_subkeys(key: int) -> list[int]:
    """Generate 16 DES subkeys from a 64-bit key."""
    # PC1 permutation (64 -> 56 bits)
    permuted = _permute(key, _PC1, 64)
    c = (permuted >> 28) & 0x0FFFFFFF
    d = permuted & 0x0FFFFFFF

    subkeys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        cd = (c << 28) | d
        subkeys.append(_permute(cd, _PC2, 56))
    return subkeys


def _des_crypt(secret: bytes, salt: str) -> str:
    """Compute traditional DES crypt hash."""
    itoa64 = _SALT_CHARS

    # Convert password to 64-bit DES key (only first 8 bytes used)
    # Each byte's lower 7 bits become key data in standard DES key format:
    # data bits at positions 7-1 (MSB end) of each byte, parity at position 0
    key_bytes = (secret[:8] + b"\x00" * 8)[:8]
    key = sum((c & 0x7F) << (57 - i * 8) for i, c in enumerate(key_bytes))

    subkeys = _make_subkeys(key)

    # Apply salt to E-box permutation
    salt_val = 0
    for i in range(2):
        c = itoa64.index(salt[i])
        salt_val |= c << (i * 6)

    # Modify E table based on salt
    e_modified = list(_E)
    for i in range(12):
        if salt_val & (1 << i):
            # Swap E[i] and E[i+24]
            e_modified[i], e_modified[i + 24] = e_modified[i + 24], e_modified[i]

    # Build modified subkeys using modified E
    # Actually, the salt modification happens during encryption, not key schedule
    # Re-implement encrypt with salt-modified E table

    block = 0  # Start with all zeros
    for _ in range(25):
        # Apply IP
        block_p = _permute(block, _IP, 64)
        left = (block_p >> 32) & 0xFFFFFFFF
        right = block_p & 0xFFFFFFFF

        for subkey in subkeys:
            expanded = _permute(right, e_modified, 32)
            expanded ^= subkey
            s_out = 0
            for j in range(8):
                bits6 = (expanded >> (42 - j * 6)) & 0x3F
                row = ((bits6 >> 5) << 1) | (bits6 & 1)
                col = (bits6 >> 1) & 0xF
                s_out = (s_out << 4) | _SBOXES[j][row * 16 + col]
            f_result = _permute(s_out, _P, 32)
            left, right = right, left ^ f_result

        combined = ((right & 0xFFFFFFFF) << 32) | (left & 0xFFFFFFFF)
        block = _permute(combined, _FP, 64)

    # Encode 64-bit result to 11-char hash using big-endian h64 encoding
    out = list(salt)
    v = block << 2  # pad to 66 bits (11 * 6)
    for off in range(60, -6, -6):
        out.append(itoa64[(v >> off) & 0x3F])

    return "".join(out)


class DesCryptHandler(AbstractHandler):
    """Traditional DES-crypt password hashing. Deprecated and disabled by default."""

    SCHEME = "des_crypt"
    disabled_by_default = True

    def hash(self, secret: str | bytes, **settings) -> str:
        secret_bytes = to_bytes(secret)
        salt = settings.get("salt")
        if salt is None:
            raw = os.urandom(2)
            salt = _SALT_CHARS[raw[0] % 64] + _SALT_CHARS[raw[1] % 64]
        salt = _validate_salt(salt, 2)
        return _des_crypt(secret_bytes, salt)

    def _verify(self, secret: str | bytes, hash: str) -> bool:
        if not self.identify(hash):
            return False
        try:
            salt = hash[:2]
        except IndexError:
            return False
        secret_bytes = to_bytes(secret)
        computed = _des_crypt(secret_bytes, salt)
        return consteq(computed, hash)

    def _identify(self, hash: str) -> bool:
        return bool(_DES_HASH_RE.match(hash))

    def needs_update(self, hash: str) -> bool:
        return True  # DES-crypt is deprecated
