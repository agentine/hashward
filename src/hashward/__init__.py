"""hashward — Modern password hashing for Python."""

from __future__ import annotations

from hashward._version import version as __version__
from hashward.context import CryptContext
from hashward.identify import identify
from hashward.registry import DEFAULT_REGISTRY

# Default context — uses argon2 as the default scheme
_default_ctx: CryptContext | None = None


def _get_default_ctx() -> CryptContext:
    global _default_ctx
    if _default_ctx is None:
        _default_ctx = CryptContext(
            schemes=DEFAULT_REGISTRY.list_schemes(),
            default="argon2",
        )
    return _default_ctx


def hash(secret: str | bytes, scheme: str = "argon2") -> str:
    """Hash a password using the specified scheme (default: argon2)."""
    return _get_default_ctx().hash(secret, scheme=scheme)


def verify(secret: str | bytes, hash_string: str) -> bool:
    """Verify a password against a hash string."""
    return _get_default_ctx().verify(secret, hash_string)


__all__ = [
    "__version__",
    "CryptContext",
    "hash",
    "identify",
    "verify",
]
