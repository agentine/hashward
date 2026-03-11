"""Tests for hashward.schemes.bcrypt (requires bcrypt)."""

import pytest

bcrypt_lib = pytest.importorskip("bcrypt")

from hashward.schemes.bcrypt import BcryptHandler, BcryptSha256Handler


class TestBcryptHandler:
    def setup_method(self):
        self.handler = BcryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=4)
        assert h.startswith("$2b$")

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$argon2id$notbcrypt") is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", rounds=12)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc", rounds=4)
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"password", rounds=4)
        assert self.handler.verify(b"password", h) is True

    def test_verify_invalid_hash(self):
        assert self.handler.verify("password", "invalid") is False


class TestBcryptSha256Handler:
    def setup_method(self):
        self.handler = BcryptSha256Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=4)
        assert h.startswith("$bcrypt-sha256$")

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notbcryptsha256") is False

    def test_long_password(self):
        """BcryptSha256 should handle passwords > 72 bytes correctly."""
        pw = "a" * 200
        h = self.handler.hash(pw, rounds=4)
        assert self.handler.verify(pw, h) is True
        # Truncated version should NOT verify (unlike plain bcrypt)
        assert self.handler.verify("a" * 72, h) is False
