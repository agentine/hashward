"""Passlib hash module compatibility.

Provides module-level handler singletons matching passlib's ``passlib.hash``
interface. Each attribute is a handler instance with ``.hash()``,
``.verify()``, ``.identify()``, and ``.needs_update()`` methods.

Usage::

    from hashward.compat import passlib_hash

    h = passlib_hash.argon2.hash("password")
    ok = passlib_hash.argon2.verify("password", h)
"""

from __future__ import annotations

from hashward.registry import DEFAULT_REGISTRY

# Lazily resolve handlers from the default registry.
# This avoids importing all scheme modules at import time.

_ALIASES = {
    "argon2": "argon2",
    "bcrypt": "bcrypt",
    "bcrypt_sha256": "bcrypt_sha256",
    "scrypt": "scrypt",
    "pbkdf2_sha256": "pbkdf2_sha256",
    "pbkdf2_sha512": "pbkdf2_sha512",
    "sha256_crypt": "sha256_crypt",
    "sha512_crypt": "sha512_crypt",
    "md5_crypt": "md5_crypt",
    "des_crypt": "des_crypt",
    "django_pbkdf2_sha256": "django_pbkdf2_sha256",
    "django_bcrypt": "django_bcrypt",
    "django_bcrypt_sha256": "django_bcrypt_sha256",
    "django_argon2": "django_argon2",
    "django_scrypt": "django_scrypt",
}

_cache: dict[str, object] = {}


def __getattr__(name: str) -> object:
    if name in _ALIASES:
        if name not in _cache:
            scheme = _ALIASES[name]
            try:
                _cache[name] = DEFAULT_REGISTRY.get(scheme)
            except Exception:
                raise AttributeError(
                    f"module 'hashward.compat.passlib_hash' has no attribute {name!r}"
                ) from None
        return _cache[name]
    raise AttributeError(
        f"module 'hashward.compat.passlib_hash' has no attribute {name!r}"
    )
