"""Compatibility layer for passlib migration.

Provides import aliases so existing passlib code can migrate to hashward
with minimal changes::

    # Before (passlib):
    from passlib.context import CryptContext
    from passlib.hash import argon2, bcrypt, pbkdf2_sha256

    # After (hashward compat):
    from hashward.compat.passlib import CryptContext
    from hashward.compat.passlib import hash as passlib_hash
    # or:
    from hashward.compat import passlib_hash
"""

from __future__ import annotations
