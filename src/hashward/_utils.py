"""Internal utilities for hashward."""

from __future__ import annotations

import base64
import hmac
import os


def consteq(a: str | bytes, b: str | bytes) -> bool:
    """Timing-safe string/bytes comparison using hmac.compare_digest."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def to_bytes(value: str | bytes) -> bytes:
    """Convert a string or bytes value to bytes (UTF-8)."""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def b64_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(data: str) -> bytes:
    """Decode URL-safe base64 (with or without padding)."""
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.urlsafe_b64decode(data)


def ab64_encode(data: bytes) -> str:
    """Encode bytes to adapted base64 (using . instead of +)."""
    return base64.b64encode(data).rstrip(b"=").decode("ascii").replace("+", ".")


def ab64_decode(data: str) -> bytes:
    """Decode adapted base64 (using . instead of +)."""
    data = data.replace(".", "+")
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.b64decode(data)


def generate_salt(size: int = 16) -> bytes:
    """Generate cryptographically random salt bytes."""
    return os.urandom(size)
