"""Tests for hashward.schemes.bcrypt (requires bcrypt)."""

import hashlib
import re

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

    def test_verify_passlib_v1_format(self):
        """Verify hashes in passlib v1 format: $bcrypt-sha256$2b,12,<salt22>$<hash31>."""
        pw = "password"
        sha_digest = hashlib.sha256(pw.encode()).hexdigest()
        salt = bcrypt_lib.gensalt(rounds=4)
        bcrypt_hash = bcrypt_lib.hashpw(sha_digest.encode("ascii"), salt).decode("ascii")
        # Parse: $2b$04$<salt22><hash31>
        m = re.match(r"^\$(2[ab]?)\$(\d+)\$(.{22})(.{31})$", bcrypt_hash)
        assert m, f"unexpected bcrypt format: {bcrypt_hash}"
        ident, rounds, salt64, checksum64 = m.groups()
        v1_hash = f"$bcrypt-sha256${ident},{rounds},{salt64}${checksum64}"
        assert self.handler.verify(pw, v1_hash) is True
        assert self.handler.verify("wrong", v1_hash) is False

    def test_verify_passlib_v2_format(self):
        """Verify hashes in passlib v2 format: $bcrypt-sha256$v=2,t=2b,r=12$<salt22>$<hash31>."""
        pw = "testpassword"
        sha_digest = hashlib.sha256(pw.encode()).hexdigest()
        salt = bcrypt_lib.gensalt(rounds=5)
        bcrypt_hash = bcrypt_lib.hashpw(sha_digest.encode("ascii"), salt).decode("ascii")
        m = re.match(r"^\$(2[ab]?)\$(\d+)\$(.{22})(.{31})$", bcrypt_hash)
        assert m, f"unexpected bcrypt format: {bcrypt_hash}"
        ident, rounds, salt64, checksum64 = m.groups()
        v2_hash = f"$bcrypt-sha256$v=2,t={ident},r={rounds}${salt64}${checksum64}"
        assert self.handler.verify(pw, v2_hash) is True
        assert self.handler.verify("wrong", v2_hash) is False

    def test_identify_passlib_formats(self):
        """Both passlib v1 and v2 formats should be identified."""
        v1 = "$bcrypt-sha256$2b,12,LJ2FY3MIQAYEKHJIT66OSYMA$abcdefghijklmnopqrstuvwxyz01234"
        v2 = "$bcrypt-sha256$v=2,t=2b,r=12$LJ2FY3MIQAYEKHJIT66OSYMA$abcdefghijklmnopqrstuvwxyz01234"
        assert self.handler.identify(v1) is True
        assert self.handler.identify(v2) is True

    def test_needs_update_passlib_formats(self):
        """needs_update should parse rounds from passlib formats."""
        pw = "password"
        sha_digest = hashlib.sha256(pw.encode()).hexdigest()
        salt = bcrypt_lib.gensalt(rounds=4)
        bcrypt_hash = bcrypt_lib.hashpw(sha_digest.encode("ascii"), salt).decode("ascii")
        m = re.match(r"^\$(2[ab]?)\$(\d+)\$(.{22})(.{31})$", bcrypt_hash)
        ident, rounds, salt64, checksum64 = m.groups()
        v1_hash = f"$bcrypt-sha256${ident},{rounds},{salt64}${checksum64}"
        assert self.handler.needs_update(v1_hash) is True  # rounds=4 < 12
