"""Tests for hashward.schemes.des_crypt (pure Python, no external deps)."""

from hashward.schemes.des_crypt import DesCryptHandler


class TestDesCryptHandler:
    def setup_method(self):
        self.handler = DesCryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password")
        assert len(h) == 13

    def test_hash_format(self):
        h = self.handler.hash("password")
        # All chars should be from the DES base64 alphabet
        import re
        assert re.match(r"^[./0-9A-Za-z]{13}$", h)

    def test_verify_correct(self):
        h = self.handler.hash("password")
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password")
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password")
        assert self.handler.identify(h) is True
        assert self.handler.identify("$1$notdes") is False
        assert self.handler.identify("short") is False

    def test_needs_update_always_true(self):
        h = self.handler.hash("password")
        assert self.handler.needs_update(h) is True

    def test_disabled_by_default(self):
        assert self.handler.disabled_by_default is True

    def test_truncates_to_8_chars(self):
        # DES only uses first 8 bytes of password
        h = self.handler.hash("password", salt="ab")
        h2 = self.handler.hash("passwordXYZ", salt="ab")
        assert h == h2

    def test_empty_password(self):
        h = self.handler.hash("")
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

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
        assert self.handler.verify("password", "") is False

    def test_explicit_salt(self):
        h = self.handler.hash("test", salt="ab")
        assert h[:2] == "ab"
