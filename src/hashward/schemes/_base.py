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

    def verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify a password against a hash.

        Returns False if hash is not a string.
        """
        if not isinstance(hash, str):
            return False
        return self._verify(secret, hash)

    @abstractmethod
    def _verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify implementation — hash is guaranteed to be a string."""

    def identify(self, hash: str) -> bool:
        """Check if a hash string belongs to this scheme.

        Returns False if hash is not a string.
        """
        if not isinstance(hash, str):
            return False
        return self._identify(hash)

    @abstractmethod
    def _identify(self, hash: str) -> bool:
        """Identify implementation — hash is guaranteed to be a string."""

    @abstractmethod
    def needs_update(self, hash: str) -> bool:
        """Check if a hash should be re-hashed with updated parameters."""
