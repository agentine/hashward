"""Type definitions and protocols for hashward."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Handler(Protocol):
    """Protocol that all scheme handlers must implement."""

    SCHEME: str

    def hash(self, secret: str | bytes, **settings) -> str:
        """Create a new hash from a password."""
        ...

    def verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify a password against a hash."""
        ...

    def identify(self, hash: str) -> bool:
        """Check if a hash string belongs to this scheme."""
        ...

    def needs_update(self, hash: str) -> bool:
        """Check if a hash should be re-hashed (outdated params)."""
        ...
