"""Tests for hashward.schemes.argon2 (requires argon2-cffi)."""

import pytest

argon2_cffi = pytest.importorskip("argon2")

from hashward.schemes.argon2 import Argon2Handler


class TestArgon2Handler:
    def setup_method(self):
        self.handler = Argon2Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password")
        assert h.startswith("$argon2id$")

    def test_verify_correct(self):
        h = self.handler.hash("password")
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password")
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password")
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notargon2") is False

    def test_needs_update_current_params(self):
        h = self.handler.hash("password")
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc")
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_empty_password(self):
        h = self.handler.hash("")
        assert self.handler.verify("", h) is True
        assert self.handler.verify("notempty", h) is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password")
        assert self.handler.verify(b"password", h) is True

    def test_custom_params(self):
        h = self.handler.hash("password", time_cost=1, memory_cost=8192, parallelism=1)
        assert self.handler.verify("password", h) is True

    def test_verify_invalid_hash(self):
        assert self.handler.verify("password", "invalid") is False
