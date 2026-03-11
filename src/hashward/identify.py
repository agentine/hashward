"""Hash identification — detect scheme from hash string prefix."""

from __future__ import annotations

# Ordered by prefix length (longest first) to avoid ambiguous matches
_PREFIX_MAP: list[tuple[str, str]] = [
    ("$argon2id$", "argon2"),
    ("$argon2i$", "argon2"),
    ("$argon2d$", "argon2"),
    ("$bcrypt-sha256$", "bcrypt_sha256"),
    ("$2b$", "bcrypt"),
    ("$2a$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$scrypt$", "scrypt"),
    ("$s0$", "scrypt"),
    ("$pbkdf2-sha256$", "pbkdf2_sha256"),
    ("$pbkdf2-sha512$", "pbkdf2_sha512"),
    ("$5$", "sha256_crypt"),
    ("$6$", "sha512_crypt"),
    ("$1$", "md5_crypt"),
]


def identify(hash_string: str) -> str | None:
    """Detect the hashing scheme from a hash string.

    Returns the scheme name (e.g. 'argon2', 'bcrypt') or None
    if the hash format is not recognized.
    """
    for prefix, scheme in _PREFIX_MAP:
        if hash_string.startswith(prefix):
            return scheme
    return None
