"""Tests for hashward.context and module-level API."""

import pytest

from hashward.context import CryptContext
from hashward.exc import UnknownSchemeError


class TestCryptContext:
    def test_hash_default_scheme(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256", "scrypt"], default="pbkdf2_sha256")
        h = ctx.hash("password")
        assert h.startswith("$pbkdf2-sha256$")

    def test_hash_explicit_scheme(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256", "scrypt"])
        h = ctx.hash("password", scheme="scrypt")
        assert h.startswith("$s0$")

    def test_verify(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256"])
        h = ctx.hash("password")
        assert ctx.verify("password", h) is True
        assert ctx.verify("wrong", h) is False

    def test_identify(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256", "scrypt"])
        h = ctx.hash("password", scheme="scrypt")
        assert ctx.identify(h) == "scrypt"

    def test_verify_unknown_hash(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256"])
        assert ctx.verify("password", "notahash") is False

    def test_needs_update_deprecated(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256", "scrypt"],
            default="scrypt",
            deprecated=["pbkdf2_sha256"],
        )
        h = ctx.hash("password", scheme="pbkdf2_sha256")
        assert ctx.needs_update(h) is True

    def test_needs_update_current(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256"])
        h = ctx.hash("password")
        assert ctx.needs_update(h) is False

    def test_verify_and_update_deprecated(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256", "scrypt"],
            default="scrypt",
            deprecated=["pbkdf2_sha256"],
        )
        h = ctx.hash("password", scheme="pbkdf2_sha256")
        valid, new_hash = ctx.verify_and_update("password", h)
        assert valid is True
        assert new_hash is not None
        assert new_hash.startswith("$s0$")

    def test_verify_and_update_wrong_password(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            deprecated=["pbkdf2_sha256"],
        )
        h = ctx.hash("password")
        valid, new_hash = ctx.verify_and_update("wrong", h)
        assert valid is False
        assert new_hash is None

    def test_verify_and_update_no_update_needed(self):
        ctx = CryptContext(schemes=["pbkdf2_sha256"])
        h = ctx.hash("password")
        valid, new_hash = ctx.verify_and_update("password", h)
        assert valid is True
        assert new_hash is None

    def test_unknown_scheme_raises(self):
        with pytest.raises(UnknownSchemeError):
            CryptContext(schemes=["nonexistent_scheme"])

    def test_unknown_default_raises(self):
        with pytest.raises(UnknownSchemeError):
            CryptContext(schemes=["pbkdf2_sha256"], default="nonexistent")


class TestModuleLevelAPI:
    def test_hash_and_verify(self):
        import hashward

        h = hashward.hash("password", scheme="pbkdf2_sha256")
        assert hashward.verify("password", h) is True
        assert hashward.verify("wrong", h) is False

    def test_identify(self):
        import hashward

        h = hashward.hash("password", scheme="scrypt")
        assert hashward.identify(h) == "scrypt"
