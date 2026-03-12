"""Tests for bug fixes in task #64."""

import pytest


class TestArgon2NonUtf8Bytes:
    """Bug 1: Argon2 handler should accept non-UTF-8 bytes passwords."""

    def test_hash_non_utf8_bytes(self):
        pytest.importorskip("argon2")
        from hashward.schemes.argon2 import Argon2Handler

        handler = Argon2Handler()
        # Latin-1 encoded bytes that are NOT valid UTF-8
        secret = b"\x80\x81\xff\xfe\xab\xcd"
        h = handler.hash(secret)
        assert h.startswith("$argon2id$")

    def test_verify_non_utf8_bytes(self):
        pytest.importorskip("argon2")
        from hashward.schemes.argon2 import Argon2Handler

        handler = Argon2Handler()
        secret = b"\x80\x81\xff\xfe\xab\xcd"
        h = handler.hash(secret)
        assert handler.verify(secret, h) is True
        assert handler.verify(b"\x80\x81\xff\xfe\xab\xce", h) is False

    def test_roundtrip_arbitrary_bytes(self):
        pytest.importorskip("argon2")
        from hashward.schemes.argon2 import Argon2Handler

        handler = Argon2Handler()
        # Every byte value
        secret = bytes(range(256))
        h = handler.hash(secret)
        assert handler.verify(secret, h) is True


class TestCryptContextIdentifyRestricted:
    """Bug 2: CryptContext.identify() should only return configured schemes."""

    def test_identify_restricted_to_schemes(self):
        from hashward.context import CryptContext

        # Only pbkdf2_sha256 is configured
        ctx = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256")

        # Hash with sha256_crypt (not in ctx schemes)
        from hashward.registry import DEFAULT_REGISTRY
        sha_handler = DEFAULT_REGISTRY.get("sha256_crypt")
        sha_hash = sha_handler.hash("password")

        # Should return None because sha256_crypt is not in ctx.schemes
        assert ctx.identify(sha_hash) is None

    def test_identify_allows_configured_scheme(self):
        from hashward.context import CryptContext

        ctx = CryptContext(schemes=["pbkdf2_sha256", "sha256_crypt"])
        h = ctx.hash("password", scheme="sha256_crypt", rounds=5000)
        assert ctx.identify(h) == "sha256_crypt"

    def test_identify_no_schemes_allows_all(self):
        from hashward.context import CryptContext

        # Empty schemes list = allow all (backward compat)
        ctx = CryptContext(schemes=[], default="pbkdf2_sha256")
        from hashward.registry import DEFAULT_REGISTRY
        sha_handler = DEFAULT_REGISTRY.get("sha256_crypt")
        sha_hash = sha_handler.hash("password")
        assert ctx.identify(sha_hash) == "sha256_crypt"

    def test_verify_restricted_scheme_returns_false(self):
        from hashward.context import CryptContext

        ctx = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256")

        # Create a sha256_crypt hash directly
        from hashward.registry import DEFAULT_REGISTRY
        sha_handler = DEFAULT_REGISTRY.get("sha256_crypt")
        sha_hash = sha_handler.hash("password")

        # ctx.verify should fail because sha256_crypt is not configured
        assert ctx.verify("password", sha_hash) is False


class TestConfigParserInterpolation:
    """Bug 3: from_string() should not interpolate %(key)s patterns."""

    def test_percent_in_value_not_interpolated(self):
        from hashward.context import CryptContext

        ini = """[hashward]
schemes = pbkdf2_sha256
default = pbkdf2_sha256
pbkdf2_sha256__rounds = 1000
"""
        # This should work without interpolation errors
        ctx = CryptContext.from_string(ini)
        assert ctx._scheme_settings["pbkdf2_sha256"]["rounds"] == 1000

    def test_percent_pattern_preserved(self):
        from hashward.context import CryptContext

        # Value containing %(foo)s should NOT be interpolated
        ini = """[hashward]
schemes = pbkdf2_sha256
default = pbkdf2_sha256
pbkdf2_sha256__custom = %(foo)s
"""
        ctx = CryptContext.from_string(ini)
        assert ctx._scheme_settings["pbkdf2_sha256"]["custom"] == "%(foo)s"


class TestDjangoArgon2NeedsUpdate:
    """Bug 4: DjangoArgon2Handler.needs_update() should check parameters."""

    def test_needs_update_with_current_params(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        h = handler.hash("password")
        # Hash with default params should not need update
        assert handler.needs_update(h) is False

    def test_needs_update_with_weak_params(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        # Hash with very weak params
        h = handler.hash("password", time_cost=1, memory_cost=1024, parallelism=1)
        # Should need update since params are weaker than defaults
        assert handler.needs_update(h) is True


class TestDjangoArgon2MalformedHash:
    """Bug #100: DjangoArgon2Handler.verify() should handle malformed argon2 hashes."""

    def test_verify_malformed_hash_returns_false(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        # A hash that starts with the Django argon2 prefix but contains
        # a malformed argon2 hash string, triggering InvalidHashError
        malformed = "argon2$not-a-valid-argon2-hash"
        assert handler.verify("password", malformed) is False

    def test_verify_truncated_hash_returns_false(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        # Truncated argon2 hash
        malformed = "argon2$$argon2id$v=19$m=102400,t=2,p=8$"
        assert handler.verify("password", malformed) is False

    def test_verify_empty_argon2_part_returns_false(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        malformed = "argon2$"
        assert handler.verify("password", malformed) is False

    def test_verify_correct_hash_still_works(self):
        pytest.importorskip("argon2")
        from hashward.schemes.django import DjangoArgon2Handler

        handler = DjangoArgon2Handler()
        h = handler.hash("password")
        assert handler.verify("password", h) is True
        assert handler.verify("wrong", h) is False
