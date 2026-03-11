"""Tests for hashward.identify."""

from hashward.identify import identify


class TestIdentify:
    def test_argon2id(self):
        assert identify("$argon2id$v=19$m=65536,t=2,p=2$salt$hash") == "argon2"

    def test_argon2i(self):
        assert identify("$argon2i$v=19$m=65536,t=2,p=2$salt$hash") == "argon2"

    def test_argon2d(self):
        assert identify("$argon2d$v=19$m=65536,t=2,p=2$salt$hash") == "argon2"

    def test_bcrypt_2b(self):
        assert identify("$2b$12$salthashsalthashsalthashsalthashsalthash") == "bcrypt"

    def test_bcrypt_2a(self):
        assert identify("$2a$12$salthashsalthashsalthashsalthashsalthash") == "bcrypt"

    def test_bcrypt_2y(self):
        assert identify("$2y$12$salthashsalthashsalthashsalthashsalthash") == "bcrypt"

    def test_bcrypt_sha256(self):
        assert identify("$bcrypt-sha256$$2b$12$salthash") == "bcrypt_sha256"

    def test_scrypt_s0(self):
        assert identify("$s0$e0801$salt$hash") == "scrypt"

    def test_pbkdf2_sha256(self):
        assert identify("$pbkdf2-sha256$29000$salt$hash") == "pbkdf2_sha256"

    def test_pbkdf2_sha512(self):
        assert identify("$pbkdf2-sha512$25000$salt$hash") == "pbkdf2_sha512"

    def test_unknown(self):
        assert identify("notahash") is None

    def test_empty(self):
        assert identify("") is None

    def test_partial_prefix(self):
        assert identify("$2") is None
