"""Hashward exceptions."""


class HashwardError(Exception):
    """Base exception for all hashward errors."""


class InvalidHashError(HashwardError):
    """Raised when a hash string is malformed or cannot be parsed."""


class UnknownSchemeError(HashwardError):
    """Raised when a hash scheme is not recognized or not registered."""


class MissingBackendError(HashwardError):
    """Raised when an optional backend library is required but not installed."""


class PasswordValueError(HashwardError):
    """Raised when a password value is invalid (e.g., contains null bytes)."""
