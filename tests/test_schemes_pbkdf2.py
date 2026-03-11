"""Tests for hashward.schemes.pbkdf2 (no external deps needed)."""

from hashward.schemes.pbkdf2 import Pbkdf2Sha256Handler, Pbkdf2Sha512Handler


class TestPbkdf2Sha256Handler:
    def setup_method(self):
        self.handler = Pbkdf2Sha256Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=1000)
        assert h.startswith("$pbkdf2-sha256$")

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notpbkdf2") is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient_rounds(self):
        h = self.handler.hash("password", rounds=600000)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc", rounds=1000)
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_empty_password(self):
        h = self.handler.hash("", rounds=1000)
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

    def test_long_password(self):
        pw = "a" * 10000
        h = self.handler.hash(pw, rounds=1000)
        assert self.handler.verify(pw, h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"password", rounds=1000)
        assert self.handler.verify(b"password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password", rounds=1000)
        h2 = self.handler.hash("password", rounds=1000)
        assert h1 != h2  # Different salts


class TestPbkdf2Sha512Handler:
    def setup_method(self):
        self.handler = Pbkdf2Sha512Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=1000)
        assert h.startswith("$pbkdf2-sha512$")

    def test_roundtrip(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.verify("password", h) is True
        assert self.handler.verify("wrong", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=1000)
        assert self.handler.identify(h) is True
