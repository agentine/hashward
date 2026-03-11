"""Tests for hashward.schemes.md5_crypt (pure Python, no external deps)."""

import pytest

from hashward.schemes.md5_crypt import Md5CryptHandler


class TestMd5CryptHandler:
    def setup_method(self):
        self.handler = Md5CryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password")
        assert h.startswith("$1$")

    def test_hash_format(self):
        h = self.handler.hash("password")
        parts = h.split("$")
        assert len(parts) == 4
        assert parts[0] == ""
        assert parts[1] == "1"
        assert len(parts[2]) <= 8  # salt max 8 chars

    def test_verify_correct(self):
        h = self.handler.hash("password")
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password")
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password")
        assert self.handler.identify(h) is True
        assert self.handler.identify("$5$notmd5") is False
        assert self.handler.identify("$2b$12$notmd5") is False

    def test_needs_update_always_true(self):
        h = self.handler.hash("password")
        assert self.handler.needs_update(h) is True

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc\u2603")
        assert self.handler.verify("\u00e9\u00e0\u00fc\u2603", h) is True
        assert self.handler.verify("wrong", h) is False

    def test_empty_password(self):
        h = self.handler.hash("")
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

    def test_long_password(self):
        pw = "a" * 10000
        h = self.handler.hash(pw)
        assert self.handler.verify(pw, h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"password")
        assert self.handler.verify(b"password", h) is True
        assert self.handler.verify("password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password")
        h2 = self.handler.hash("password")
        assert h1 != h2  # Different salts

    def test_verify_invalid_hash(self):
        assert self.handler.verify("password", "invalid") is False
        assert self.handler.verify("password", "$1$") is False

    def test_salt_truncation(self):
        h = self.handler.hash("password", salt="abcdefghijklmnop")
        parts = h.split("$")
        assert len(parts[2]) == 8  # Truncated to 8

    def test_salt_invalid_chars_rejected(self):
        with pytest.raises(ValueError, match="Invalid salt character"):
            self.handler.hash("password", salt="abc$def")

    def test_salt_dollar_corrupts_format(self):
        """A $ in the salt would corrupt the hash format."""
        with pytest.raises(ValueError, match="Invalid salt character"):
            self.handler.hash("password", salt="sa$t1234")
