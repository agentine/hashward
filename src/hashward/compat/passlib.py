"""Passlib-compatible import aliases.

Usage::

    from hashward.compat.passlib import CryptContext
    from hashward.compat.passlib import hash as passlib_hash

    ctx = CryptContext(schemes=["argon2", "bcrypt"])
    h = passlib_hash.argon2.hash("password")
    ok = passlib_hash.argon2.verify("password", h)
"""

from __future__ import annotations

from hashward.context import CryptContext
from hashward.compat import passlib_hash as hash  # noqa: A001

__all__ = ["CryptContext", "hash"]
