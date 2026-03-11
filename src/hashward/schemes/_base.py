"""Base handler class for hashward schemes."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AbstractHandler(ABC):
    """Abstract base class for scheme handlers.

    All scheme handlers should inherit from this class and implement
    the required methods.
    """

    SCHEME: str = ""

    @abstractmethod
    def hash(self, secret: str | bytes, **settings) -> str:
        """Create a new hash from a password."""

    @abstractmethod
    def verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify a password against a hash."""

    @abstractmethod
    def identify(self, hash: str) -> bool:
        """Check if a hash string belongs to this scheme."""

    @abstractmethod
    def needs_update(self, hash: str) -> bool:
        """Check if a hash should be re-hashed with updated parameters."""
