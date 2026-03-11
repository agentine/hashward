"""Scheme registry with lazy loading."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hashward.exc import UnknownSchemeError

if TYPE_CHECKING:
    from hashward._types import Handler


# Maps scheme name -> (module_path, class_name) for lazy imports
_BUILTIN_SCHEMES: dict[str, tuple[str, str]] = {
    "argon2": ("hashward.schemes.argon2", "Argon2Handler"),
    "bcrypt": ("hashward.schemes.bcrypt", "BcryptHandler"),
    "bcrypt_sha256": ("hashward.schemes.bcrypt", "BcryptSha256Handler"),
    "scrypt": ("hashward.schemes.scrypt", "ScryptHandler"),
    "pbkdf2_sha256": ("hashward.schemes.pbkdf2", "Pbkdf2Sha256Handler"),
    "pbkdf2_sha512": ("hashward.schemes.pbkdf2", "Pbkdf2Sha512Handler"),
}


class SchemeRegistry:
    """Registry for password hashing scheme handlers.

    Supports lazy loading — handler modules are imported only when
    a scheme is first accessed.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}
        self._lazy: dict[str, tuple[str, str]] = {}

    def register(self, name: str, handler: Handler) -> None:
        """Register an instantiated handler."""
        self._handlers[name] = handler

    def register_lazy(self, name: str, module_path: str, class_name: str) -> None:
        """Register a handler for lazy loading."""
        self._lazy[name] = (module_path, class_name)

    def get(self, name: str) -> Handler:
        """Get a handler by scheme name. Lazy-loads if needed."""
        if name in self._handlers:
            return self._handlers[name]

        if name in self._lazy:
            module_path, class_name = self._lazy[name]
            import importlib
            module = importlib.import_module(module_path)
            handler_class = getattr(module, class_name)
            handler = handler_class()
            self._handlers[name] = handler
            return handler

        raise UnknownSchemeError(f"Unknown scheme: {name!r}")

    def list_schemes(self) -> list[str]:
        """List all registered scheme names."""
        names = set(self._handlers.keys()) | set(self._lazy.keys())
        return sorted(names)

    def __contains__(self, name: str) -> bool:
        return name in self._handlers or name in self._lazy


def _make_default_registry() -> SchemeRegistry:
    """Create the default registry with all built-in schemes."""
    registry = SchemeRegistry()
    for name, (module_path, class_name) in _BUILTIN_SCHEMES.items():
        registry.register_lazy(name, module_path, class_name)
    return registry


DEFAULT_REGISTRY = _make_default_registry()
