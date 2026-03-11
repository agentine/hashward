"""Tests for advanced CryptContext features — per-scheme settings, using(), INI config."""

import pytest

from hashward.context import CryptContext
from hashward.exc import PasswordValueError


class TestPerSchemeSettings:
    def test_per_scheme_settings_applied(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__rounds=1000,
        )
        h = ctx.hash("password")
        # Should use 1000 rounds (from settings), not 600000 (default)
        assert "$1000$" in h

    def test_call_time_settings_override(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__rounds=1000,
        )
        h = ctx.hash("password", rounds=2000)
        assert "$2000$" in h


class TestUsing:
    def test_using_returns_new_context(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__rounds=1000,
        )
        ctx2 = ctx.using(pbkdf2_sha256__rounds=2000)
        # Original unchanged
        h1 = ctx.hash("password")
        assert "$1000$" in h1
        # New context uses 2000
        h2 = ctx2.hash("password")
        assert "$2000$" in h2

    def test_using_override_default(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256", "sha256_crypt"],
            default="pbkdf2_sha256",
        )
        ctx2 = ctx.using(default="sha256_crypt")
        h = ctx2.hash("password", rounds=5000)
        assert h.startswith("$5$")

    def test_copy_is_alias_for_using(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__rounds=1000,
        )
        ctx2 = ctx.copy(pbkdf2_sha256__rounds=3000)
        h = ctx2.hash("password")
        assert "$3000$" in h


class TestTruncateError:
    def test_truncate_error_raises_on_long_password(self):
        ctx = CryptContext(
            schemes=["bcrypt"],
            default="bcrypt",
            truncate_error=True,
        )
        long_pw = "a" * 100
        with pytest.raises(PasswordValueError, match="72-byte"):
            ctx.hash(long_pw)

    def test_truncate_error_allows_short_password(self):
        ctx = CryptContext(
            schemes=["bcrypt"],
            default="bcrypt",
            truncate_error=True,
        )
        h = ctx.hash("short", rounds=4)
        assert h.startswith("$2b$")


class TestINIConfig:
    def test_to_string_basic(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256", "bcrypt"],
            default="pbkdf2_sha256",
            deprecated=["bcrypt"],
        )
        ini = ctx.to_string()
        assert "[hashward]" in ini
        assert "schemes = pbkdf2_sha256, bcrypt" in ini
        assert "default = pbkdf2_sha256" in ini
        assert "deprecated = bcrypt" in ini

    def test_to_string_with_scheme_settings(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__rounds=1000,
        )
        ini = ctx.to_string()
        assert "pbkdf2_sha256__rounds = 1000" in ini

    def test_from_string_basic(self):
        ini = """[hashward]
schemes = pbkdf2_sha256, sha256_crypt
default = pbkdf2_sha256
deprecated = sha256_crypt
"""
        ctx = CryptContext.from_string(ini)
        assert ctx._schemes == ["pbkdf2_sha256", "sha256_crypt"]
        assert ctx._default == "pbkdf2_sha256"
        assert "sha256_crypt" in ctx._deprecated

    def test_from_string_with_scheme_settings(self):
        ini = """[hashward]
schemes = pbkdf2_sha256
default = pbkdf2_sha256
pbkdf2_sha256__rounds = 1000
"""
        ctx = CryptContext.from_string(ini)
        h = ctx.hash("password")
        assert "$1000$" in h

    def test_roundtrip(self):
        ctx = CryptContext(
            schemes=["pbkdf2_sha256", "sha256_crypt"],
            default="pbkdf2_sha256",
            deprecated=["sha256_crypt"],
            pbkdf2_sha256__rounds=5000,
        )
        ini = ctx.to_string()
        ctx2 = CryptContext.from_string(ini)
        assert ctx2._schemes == ctx._schemes
        assert ctx2._default == ctx._default
        assert ctx2._deprecated == ctx._deprecated
        h = ctx2.hash("password")
        assert "$5000$" in h

    def test_from_string_missing_section_raises(self):
        with pytest.raises(ValueError, match="hashward"):
            CryptContext.from_string("[other]\nfoo = bar\n")

    def test_to_string_with_truncate_error(self):
        ctx = CryptContext(
            schemes=["bcrypt"],
            default="bcrypt",
            truncate_error=True,
        )
        ini = ctx.to_string()
        assert "truncate_error = true" in ini

    def test_from_string_with_truncate_error(self):
        ini = """[hashward]
schemes = bcrypt
default = bcrypt
truncate_error = true
"""
        ctx = CryptContext.from_string(ini)
        assert ctx._truncate_error is True
