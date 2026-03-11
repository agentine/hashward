"""Tests for hashward.schemes.django — Django-compatible password hashers."""

from hashward.schemes.django import (
    DjangoArgon2Handler,
    DjangoBcryptHandler,
    DjangoBcryptSha256Handler,
    DjangoPbkdf2Sha256Handler,
    DjangoScryptHandler,
)


class TestDjangoPbkdf2Sha256Handler:
    def setup_method(self):
        self.handler = DjangoPbkdf2Sha256Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", iterations=1000)
        assert h.startswith("pbkdf2_sha256$")

    def test_hash_format(self):
        h = self.handler.hash("password", iterations=1000)
        parts = h.split("$")
        assert len(parts) == 4
        assert parts[0] == "pbkdf2_sha256"
        assert parts[1] == "1000"

    def test_verify_correct(self):
        h = self.handler.hash("password", iterations=1000)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", iterations=1000)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", iterations=1000)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notdjango") is False

    def test_needs_update_low_iterations(self):
        h = self.handler.hash("password", iterations=1000)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", iterations=600000)
        assert self.handler.needs_update(h) is False

    def test_unicode_password(self):
        h = self.handler.hash("\u00e9\u00e0\u00fc", iterations=1000)
        assert self.handler.verify("\u00e9\u00e0\u00fc", h) is True

    def test_bytes_password(self):
        h = self.handler.hash(b"password", iterations=1000)
        assert self.handler.verify(b"password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password", iterations=1000)
        h2 = self.handler.hash("password", iterations=1000)
        assert h1 != h2


class TestDjangoBcryptHandler:
    def setup_method(self):
        self.handler = DjangoBcryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=4)
        assert h.startswith("bcrypt$")

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.identify(h) is True
        assert self.handler.identify("$2b$12$notdjango") is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", rounds=12)
        assert self.handler.needs_update(h) is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password", rounds=4)
        assert self.handler.verify(b"password", h) is True


class TestDjangoBcryptSha256Handler:
    def setup_method(self):
        self.handler = DjangoBcryptSha256Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password", rounds=4)
        assert h.startswith("bcrypt_sha256$")

    def test_verify_correct(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.identify(h) is True
        # Should not match plain bcrypt$ prefix
        assert self.handler.identify("bcrypt$something") is False

    def test_identify_rejects_plain_bcrypt(self):
        """DjangoBcryptHandler should NOT identify bcrypt_sha256$ hashes."""
        h = self.handler.hash("password", rounds=4)
        plain_handler = DjangoBcryptHandler()
        assert plain_handler.identify(h) is False

    def test_long_password(self):
        """SHA-256 pre-hash handles passwords > 72 bytes."""
        pw = "a" * 200
        h = self.handler.hash(pw, rounds=4)
        assert self.handler.verify(pw, h) is True
        assert self.handler.verify("a" * 72, h) is False

    def test_needs_update_low_rounds(self):
        h = self.handler.hash("password", rounds=4)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", rounds=12)
        assert self.handler.needs_update(h) is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password", rounds=4)
        assert self.handler.verify(b"password", h) is True


class TestDjangoArgon2Handler:
    def setup_method(self):
        self.handler = DjangoArgon2Handler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password")
        assert h.startswith("argon2$")

    def test_verify_correct(self):
        h = self.handler.hash("password")
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password")
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password")
        assert self.handler.identify(h) is True
        assert self.handler.identify("$argon2id$notdjango") is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password")
        assert self.handler.verify(b"password", h) is True


class TestDjangoScryptHandler:
    def setup_method(self):
        self.handler = DjangoScryptHandler()

    def test_hash_produces_valid_string(self):
        h = self.handler.hash("password")
        assert h.startswith("scrypt$")

    def test_hash_format(self):
        h = self.handler.hash("password")
        parts = h.split("$")
        assert len(parts) == 6
        assert parts[0] == "scrypt"

    def test_verify_correct(self):
        h = self.handler.hash("password")
        assert self.handler.verify("password", h) is True

    def test_verify_wrong(self):
        h = self.handler.hash("password")
        assert self.handler.verify("wrongpassword", h) is False

    def test_identify(self):
        h = self.handler.hash("password")
        assert self.handler.identify(h) is True
        # Should not match hashward native $scrypt$ format
        assert self.handler.identify("$scrypt$notdjango") is False

    def test_needs_update_low_n(self):
        h = self.handler.hash("password", n=1024)
        assert self.handler.needs_update(h) is True

    def test_needs_update_sufficient(self):
        h = self.handler.hash("password", n=2**14)
        assert self.handler.needs_update(h) is False

    def test_bytes_password(self):
        h = self.handler.hash(b"password")
        assert self.handler.verify(b"password", h) is True

    def test_unique_hashes(self):
        h1 = self.handler.hash("password")
        h2 = self.handler.hash("password")
        assert h1 != h2
