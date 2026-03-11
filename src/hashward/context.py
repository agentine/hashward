"""CryptContext — multi-scheme policy manager for password hashing."""

from __future__ import annotations

from hashward.exc import UnknownSchemeError
from hashward.identify import identify as _identify
from hashward.registry import DEFAULT_REGISTRY, SchemeRegistry


class CryptContext:
    """Policy manager for password hashing.

    Manages multiple hashing schemes, allowing configuration of which
    schemes are active, which is the default, and which are deprecated.
    """

    def __init__(
        self,
        schemes: list[str] | None = None,
        default: str | None = None,
        deprecated: list[str] | None = None,
        registry: SchemeRegistry | None = None,
    ) -> None:
        self._registry = registry or DEFAULT_REGISTRY
        self._schemes = schemes or []
        self._deprecated = set(deprecated or [])

        if default is not None:
            self._default = default
        elif self._schemes:
            self._default = self._schemes[0]
        else:
            self._default = "argon2"

        # Validate that all configured schemes exist in registry
        for scheme in self._schemes:
            if scheme not in self._registry:
                raise UnknownSchemeError(f"Unknown scheme: {scheme!r}")
        if self._default not in self._registry:
            raise UnknownSchemeError(f"Unknown default scheme: {self._default!r}")

    def hash(self, secret: str | bytes, scheme: str | None = None) -> str:
        """Hash a password using the specified or default scheme."""
        scheme = scheme or self._default
        handler = self._registry.get(scheme)
        return handler.hash(secret)

    def verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify a password against a hash.

        Automatically identifies the scheme from the hash string.
        """
        scheme = self.identify(hash)
        if scheme is None:
            return False
        handler = self._registry.get(scheme)
        return handler.verify(secret, hash)

    def identify(self, hash: str) -> str | None:
        """Identify the scheme of a hash string."""
        return _identify(hash)

    def needs_update(self, hash: str) -> bool:
        """Check if a hash needs to be re-hashed.

        Returns True if the hash uses a deprecated scheme or if the
        handler reports that its parameters are outdated.
        """
        scheme = self.identify(hash)
        if scheme is None:
            return True
        if scheme in self._deprecated:
            return True
        handler = self._registry.get(scheme)
        return handler.needs_update(hash)

    def verify_and_update(
        self, secret: str | bytes, hash: str
    ) -> tuple[bool, str | None]:
        """Verify a password and return a new hash if an update is needed.

        Returns (valid, new_hash) where new_hash is None if no update
        is needed, or a new hash string if the existing hash should be
        replaced.
        """
        valid = self.verify(secret, hash)
        if not valid:
            return False, None
        if self.needs_update(hash):
            new_hash = self.hash(secret)
            return True, new_hash
        return True, None
