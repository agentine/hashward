"""Tests for hashward.schemes.scrypt (no external deps needed)."""

from hashward.schemes.scrypt import ScryptHandler


class TestScryptHandler:
    def setup_method(self):
        self.handler = ScryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", n=1024)
        assert h.startswith("$s0$")

    def test_verify_correct(self):
        h = self.handler.hash("password", n=1024)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", n=1024)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", n=1024)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notscrypt") is False

    def test_needs_update_low_n(self):
        h = self.handler.hash("password", n=1024)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", n=16384)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc", n=1024)
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_empty_password(self):
        h = self.handler.hash("", n=1024)
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password", n=1024)
        assert self.handler.verify(b"password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password", n=1024)
        h2 = self.handler.hash("password", n=1024)
        assert h1 != h2
