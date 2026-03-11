"""CryptContext — multi-scheme policy manager for password hashing."""

from __future__ import annotations

import configparser
import time

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
        min_verify_time: float = 0,
        truncate_error: bool = False,
        **settings,
    ) -> None:
        self._registry = registry or DEFAULT_REGISTRY
        self._schemes = schemes or []
        self._deprecated = set(deprecated or [])
        self._min_verify_time = min_verify_time
        self._truncate_error = truncate_error

        if default is not None:
            self._default = default
        elif self._schemes:
            self._default = self._schemes[0]
        else:
            self._default = "argon2"

        # Parse per-scheme settings: argon2__time_cost=3 -> {"argon2": {"time_cost": 3}}
        self._scheme_settings: dict[str, dict] = {}
        for key, value in settings.items():
            if "__" in key:
                scheme_name, param = key.split("__", 1)
                self._scheme_settings.setdefault(scheme_name, {})[param] = value

        # Validate that all configured schemes exist in registry
        for scheme in self._schemes:
            if scheme not in self._registry:
                raise UnknownSchemeError(f"Unknown scheme: {scheme!r}")
        if self._default not in self._registry:
            raise UnknownSchemeError(f"Unknown default scheme: {self._default!r}")

    def hash(self, secret: str | bytes, scheme: str | None = None, **settings) -> str:
        """Hash a password using the specified or default scheme."""
        scheme = scheme or self._default
        handler = self._registry.get(scheme)

        # Merge per-scheme settings with call-time settings
        merged = dict(self._scheme_settings.get(scheme, {}))
        merged.update(settings)

        if self._truncate_error and scheme in ("bcrypt", "django_bcrypt"):
            from hashward._utils import to_bytes
            if len(to_bytes(secret)) > 72:
                from hashward.exc import PasswordValueError
                raise PasswordValueError("Password exceeds bcrypt's 72-byte limit")

        return handler.hash(secret, **merged)

    def verify(self, secret: str | bytes, hash: str) -> bool:
        """Verify a password against a hash.

        Automatically identifies the scheme from the hash string.
        """
        start = time.monotonic()
        scheme = self.identify(hash)
        if scheme is None:
            result = False
        else:
            handler = self._registry.get(scheme)
            result = handler.verify(secret, hash)

        if self._min_verify_time > 0:
            elapsed = time.monotonic() - start
            remaining = self._min_verify_time - elapsed
            if remaining > 0:
                time.sleep(remaining)

        return result

    def identify(self, hash: str) -> str | None:
        """Identify the scheme of a hash string.

        Only returns schemes that are configured in this context.
        """
        scheme = _identify(hash)
        if scheme is not None and self._schemes and scheme not in self._schemes:
            return None
        return scheme

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

    def using(self, **overrides) -> CryptContext:
        """Return a new CryptContext with overridden settings."""
        kwargs: dict = {
            "schemes": overrides.pop("schemes", self._schemes),
            "default": overrides.pop("default", self._default),
            "deprecated": overrides.pop("deprecated", list(self._deprecated)),
            "registry": overrides.pop("registry", self._registry),
            "min_verify_time": overrides.pop("min_verify_time", self._min_verify_time),
            "truncate_error": overrides.pop("truncate_error", self._truncate_error),
        }

        # Merge existing per-scheme settings with overrides
        merged_settings: dict = {}
        for scheme, params in self._scheme_settings.items():
            for param, value in params.items():
                merged_settings[f"{scheme}__{param}"] = value
        merged_settings.update(overrides)
        kwargs.update(merged_settings)

        return CryptContext(**kwargs)

    def copy(self, **overrides) -> CryptContext:
        """Alias for using()."""
        return self.using(**overrides)

    def to_string(self) -> str:
        """Serialize config as INI-format string (passlib-compatible)."""
        lines = ["[hashward]"]
        if self._schemes:
            lines.append(f"schemes = {', '.join(self._schemes)}")
        lines.append(f"default = {self._default}")
        if self._deprecated:
            lines.append(f"deprecated = {', '.join(sorted(self._deprecated))}")
        if self._min_verify_time:
            lines.append(f"min_verify_time = {self._min_verify_time}")
        if self._truncate_error:
            lines.append("truncate_error = true")

        for scheme in sorted(self._scheme_settings):
            for param in sorted(self._scheme_settings[scheme]):
                value = self._scheme_settings[scheme][param]
                lines.append(f"{scheme}__{param} = {value}")

        return "\n".join(lines) + "\n"

    @classmethod
    def from_string(cls, ini_str: str, registry: SchemeRegistry | None = None) -> CryptContext:
        """Create a CryptContext from an INI-format config string."""
        parser = configparser.RawConfigParser()
        parser.read_string(ini_str)

        section = "hashward"
        if not parser.has_section(section):
            raise ValueError("INI config must have a [hashward] section")

        kwargs: dict = {}
        if registry is not None:
            kwargs["registry"] = registry

        reserved = {"schemes", "default", "deprecated", "min_verify_time", "truncate_error"}

        if parser.has_option(section, "schemes"):
            kwargs["schemes"] = [s.strip() for s in parser.get(section, "schemes").split(",")]

        if parser.has_option(section, "default"):
            kwargs["default"] = parser.get(section, "default").strip()

        if parser.has_option(section, "deprecated"):
            kwargs["deprecated"] = [s.strip() for s in parser.get(section, "deprecated").split(",")]

        if parser.has_option(section, "min_verify_time"):
            kwargs["min_verify_time"] = parser.getfloat(section, "min_verify_time")

        if parser.has_option(section, "truncate_error"):
            kwargs["truncate_error"] = parser.getboolean(section, "truncate_error")

        # Collect per-scheme settings (keys with __ in them)
        for key in parser.options(section):
            if "__" in key and key not in reserved:
                value = parser.get(section, key)
                try:
                    kwargs[key] = int(value)
                except ValueError:
                    try:
                        kwargs[key] = float(value)
                    except ValueError:
                        kwargs[key] = value

        return cls(**kwargs)
