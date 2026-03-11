"""Tests for hashward.schemes.sha_crypt (pure Python, no external deps)."""

import pytest

from hashward.schemes.sha_crypt import Sha256CryptHandler, Sha512CryptHandler


class TestSha256CryptHandler:
    def setup_method(self):
        self.handler = Sha256CryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=5000)
        assert h.startswith("$5$")

    def test_hash_with_explicit_rounds(self):
        h = self.handler.hash("password", rounds=10000)
        assert "$5$rounds=10000$" in h

    def test_hash_default_rounds_omits_5000(self):
        # rounds=5000 is the default and should not appear in hash
        h = self.handler.hash("password", rounds=5000)
        assert "rounds=" not in h

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$6$notsha256") is False
        assert self.handler.identify("$2b$12$notsha256") is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient_rounds(self):
        h = self.handler.hash("password", rounds=535000)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc\u2603", rounds=5000)
        assert self.handler.verify("\u00e9\u00e0\u00fc\u2603", h) is True
        assert self.handler.verify("wrong", h) is False

    def test_empty_password(self):
        h = self.handler.hash("", rounds=5000)
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

    def test_long_password(self):
        pw = "a" * 10000
        h = self.handler.hash(pw, rounds=5000)
        assert self.handler.verify(pw, h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"password", rounds=5000)
        assert self.handler.verify(b"password", h) is True
        assert self.handler.verify("password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password", rounds=5000)
        h2 = self.handler.hash("password", rounds=5000)
        assert h1 != h2  # Different salts

    def test_verify_invalid_hash(self):
        assert self.handler.verify("password", "invalid") is False
        assert self.handler.verify("password", "$5$") is False


class TestSha512CryptHandler:
    def setup_method(self):
        self.handler = Sha512CryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=5000)
        assert h.startswith("$6$")

    def test_roundtrip(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.verify("password", h) is True
        assert self.handler.verify("wrong", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$5$notsha512") is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=5000)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", rounds=656000)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc", rounds=5000)
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_empty_password(self):
        h = self.handler.hash("", rounds=5000)
        assert self.handler.verify("", h) is True

    def test_long_password(self):
        pw = "b" * 10000
        h = self.handler.hash(pw, rounds=5000)
        assert self.handler.verify(pw, h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"test", rounds=5000)
        assert self.handler.verify(b"test", h) is True


class TestShaCryptSaltValidation:
    """Salt length truncation and character validation for SHA-crypt."""

    def test_salt_truncated_to_16_chars(self):
        handler = Sha256CryptHandler()
        h = handler.hash("password", salt="a" * 32, rounds=5000)
        parts = h.split("$")
        # $5$salt$hash -> ['', '5', 'salt', 'hash']
        assert len(parts[2]) == 16

    def test_salt_truncated_sha512(self):
        handler = Sha512CryptHandler()
        h = handler.hash("password", salt="b" * 20, rounds=5000)
        parts = h.split("$")
        assert len(parts[2]) == 16

    def test_salt_invalid_chars_rejected(self):
        handler = Sha256CryptHandler()
        with pytest.raises(ValueError, match="Invalid salt character"):
            handler.hash("password", salt="abc$def", rounds=5000)

    def test_salt_dollar_rejected(self):
        handler = Sha512CryptHandler()
        with pytest.raises(ValueError, match="Invalid salt character"):
            handler.hash("password", salt="salt$corrupt", rounds=5000)

    def test_salt_space_rejected(self):
        handler = Sha256CryptHandler()
        with pytest.raises(ValueError, match="Invalid salt character"):
            handler.hash("password", salt="salt with space", rounds=5000)

    def test_valid_salt_accepted(self):
        handler = Sha256CryptHandler()
        h = handler.hash("password", salt="abcABC012./xyz", rounds=5000)
        assert handler.verify("password", h) is True
