"""Plaintext password handler — for testing/migration only.

Not registered in DEFAULT_REGISTRY by default.
"""

from __future__ import annotations

from hashward._utils import consteq
from hashward.schemes._base import AbstractHandler

_PREFIX = "plain:"


class PlaintextHandler(AbstractHandler):
    """Plaintext password storage. For testing/migration only."""

    SCHEME = "plaintext"
    disabled_by_default = True

    def hash(self, secret: str | bytes, **settings) -> str:
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8")
        return f"{_PREFIX}{secret}"

    def _verify(self, secret: str | bytes, hash: str) -> bool:
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8")
        if hash.startswith(_PREFIX):
            stored = hash[len(_PREFIX):]
        else:
            stored = hash
        return consteq(stored, secret)

    def _identify(self, hash: str) -> bool:
        return hash.startswith(_PREFIX)

    def needs_update(self, hash: str) -> bool:
        return True  # Plaintext is always upgradeable
