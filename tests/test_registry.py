"""Tests for hashward.registry."""

import pytest

from hashward.exc import UnknownSchemeError
from hashward.registry import DEFAULT_REGISTRY, SchemeRegistry


class TestSchemeRegistry:
    def test_register_and_get(self):
        class FakeHandler:
            SCHEME = "fake"
            def hash(self, secret, **s): return "fakehash"
            def verify(self, secret, hash): return True
            def identify(self, hash): return True
            def needs_update(self, hash): return False

        reg = SchemeRegistry()
        handler = FakeHandler()
        reg.register("fake", handler)
        assert reg.get("fake") is handler

    def test_unknown_scheme_raises(self):
        reg = SchemeRegistry()
        with pytest.raises(UnknownSchemeError, match="nonexistent"):
            reg.get("nonexistent")

    def test_list_schemes(self):
        reg = SchemeRegistry()
        reg.register_lazy("a", "mod", "Cls")
        reg.register_lazy("b", "mod", "Cls")
        assert reg.list_schemes() == ["a", "b"]

    def test_contains(self):
        reg = SchemeRegistry()
        reg.register_lazy("test", "mod", "Cls")
        assert "test" in reg
        assert "missing" not in reg


class TestDefaultRegistry:
    def test_builtin_schemes_registered(self):
        expected = {
            "argon2", "bcrypt", "bcrypt_sha256", "pbkdf2_sha256", "pbkdf2_sha512", "scrypt",
            "sha256_crypt", "sha512_crypt", "md5_crypt",
            "django_pbkdf2_sha256", "django_bcrypt", "django_argon2", "django_scrypt",
        }
        assert expected == set(DEFAULT_REGISTRY.list_schemes())

    def test_lazy_load_pbkdf2(self):
        handler = DEFAULT_REGISTRY.get("pbkdf2_sha256")
        assert handler.SCHEME == "pbkdf2_sha256"
