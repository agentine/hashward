"""Tests for the passlib compatibility layer."""

import pytest


class TestCryptContextImport:
    """Verify CryptContext can be imported from compat path."""

    def test_import_from_compat_passlib(self):
        from hashward.compat.passlib import CryptContext

        ctx = CryptContext(schemes=["pbkdf2_sha256"])
        h = ctx.hash("test")
        assert ctx.verify("test", h)

    def test_crypt_context_is_same_class(self):
        from hashward.compat.passlib import CryptContext
        from hashward.context import CryptContext as RealCryptContext

        assert CryptContext is RealCryptContext


class TestPasslibHash:
    """Verify passlib.hash.* style handler access."""

    def test_import_hash_module(self):
        from hashward.compat import passlib_hash

        assert hasattr(passlib_hash, "pbkdf2_sha256")

    def test_hash_via_passlib_hash(self):
        from hashward.compat.passlib import hash as passlib_hash

        h = passlib_hash.pbkdf2_sha256.hash("password")
        assert passlib_hash.pbkdf2_sha256.verify("password", h)

    def test_hash_via_module_import(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.pbkdf2_sha256.hash("password")
        assert passlib_hash.pbkdf2_sha256.verify("password", h)

    def test_pbkdf2_sha512(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.pbkdf2_sha512.hash("password")
        assert passlib_hash.pbkdf2_sha512.verify("password", h)

    def test_sha256_crypt(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.sha256_crypt.hash("password")
        assert passlib_hash.sha256_crypt.verify("password", h)

    def test_sha512_crypt(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.sha512_crypt.hash("password")
        assert passlib_hash.sha512_crypt.verify("password", h)

    def test_md5_crypt(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.md5_crypt.hash("password")
        assert passlib_hash.md5_crypt.verify("password", h)

    def test_des_crypt(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.des_crypt.hash("password")
        assert passlib_hash.des_crypt.verify("password", h)

    def test_unknown_attribute_raises(self):
        from hashward.compat import passlib_hash

        with pytest.raises(AttributeError):
            passlib_hash.nonexistent_scheme


class TestPasslibHashBcrypt:
    """bcrypt-based tests (require bcrypt package)."""

    def test_bcrypt_hash_verify(self):
        pytest.importorskip("bcrypt")
        from hashward.compat import passlib_hash

        h = passlib_hash.bcrypt.hash("password")
        assert passlib_hash.bcrypt.verify("password", h)
        assert not passlib_hash.bcrypt.verify("wrong", h)

    def test_bcrypt_sha256_hash_verify(self):
        pytest.importorskip("bcrypt")
        from hashward.compat import passlib_hash

        h = passlib_hash.bcrypt_sha256.hash("password")
        assert passlib_hash.bcrypt_sha256.verify("password", h)


class TestPasslibHashArgon2:
    """argon2-based tests (require argon2-cffi package)."""

    def test_argon2_hash_verify(self):
        pytest.importorskip("argon2")
        from hashward.compat import passlib_hash

        h = passlib_hash.argon2.hash("password")
        assert passlib_hash.argon2.verify("password", h)
        assert not passlib_hash.argon2.verify("wrong", h)


class TestPasslibHashDjangoSchemes:
    """Tests for Django scheme aliases in passlib_hash (bug #113)."""

    def test_django_pbkdf2_sha256_accessible(self):
        from hashward.compat import passlib_hash

        handler = passlib_hash.django_pbkdf2_sha256
        h = handler.hash("password")
        assert handler.verify("password", h)
        assert not handler.verify("wrong", h)

    def test_django_bcrypt_accessible(self):
        pytest.importorskip("bcrypt")
        from hashward.compat import passlib_hash

        handler = passlib_hash.django_bcrypt
        h = handler.hash("password")
        assert handler.verify("password", h)
        assert not handler.verify("wrong", h)

    def test_django_bcrypt_sha256_accessible(self):
        pytest.importorskip("bcrypt")
        from hashward.compat import passlib_hash

        handler = passlib_hash.django_bcrypt_sha256
        h = handler.hash("password")
        assert handler.verify("password", h)
        assert not handler.verify("wrong", h)

    def test_django_argon2_accessible(self):
        pytest.importorskip("argon2")
        from hashward.compat import passlib_hash

        handler = passlib_hash.django_argon2
        h = handler.hash("password")
        assert handler.verify("password", h)
        assert not handler.verify("wrong", h)

    def test_django_scrypt_accessible(self):
        from hashward.compat import passlib_hash

        handler = passlib_hash.django_scrypt
        h = handler.hash("password")
        assert handler.verify("password", h)
        assert not handler.verify("wrong", h)

    def test_all_registry_schemes_in_aliases(self):
        """All schemes in DEFAULT_REGISTRY must be accessible via passlib_hash."""
        from hashward.compat import passlib_hash
        from hashward.registry import DEFAULT_REGISTRY

        for scheme in DEFAULT_REGISTRY.list_schemes():
            assert hasattr(passlib_hash, scheme), (
                f"Scheme {scheme!r} is in DEFAULT_REGISTRY but not accessible "
                f"via passlib_hash"
            )


class TestKnownPasslibHashes:
    """Verify hashward can verify hashes generated by passlib (known vectors)."""

    def test_verify_passlib_pbkdf2_sha256(self):
        from hashward.compat import passlib_hash

        # passlib pbkdf2_sha256 format: $pbkdf2-sha256$rounds$salt$hash
        h = passlib_hash.pbkdf2_sha256.hash("password")
        assert h.startswith("$pbkdf2-sha256$")
        assert passlib_hash.pbkdf2_sha256.verify("password", h)

    def test_verify_passlib_sha256_crypt(self):
        from hashward.compat import passlib_hash

        # sha256_crypt format: $5$rounds=NNN$salt$hash
        h = passlib_hash.sha256_crypt.hash("password")
        assert h.startswith("$5$")
        assert passlib_hash.sha256_crypt.verify("password", h)

    def test_verify_passlib_md5_crypt(self):
        from hashward.compat import passlib_hash

        # md5_crypt format: $1$salt$hash
        h = passlib_hash.md5_crypt.hash("password")
        assert h.startswith("$1$")
        assert passlib_hash.md5_crypt.verify("password", h)


class TestRoundTrip:
    """Hash then verify — ensure all schemes round-trip correctly."""

    @pytest.mark.parametrize(
        "scheme",
        ["pbkdf2_sha256", "pbkdf2_sha512", "sha256_crypt", "sha512_crypt", "md5_crypt", "des_crypt"],
    )
    def test_round_trip(self, scheme):
        from hashward.compat import passlib_hash

        handler = getattr(passlib_hash, scheme)
        h = handler.hash("test-password-123")
        assert handler.verify("test-password-123", h)
        assert not handler.verify("wrong-password", h)


class TestEdgeCases:
    """Edge cases: empty, unicode, long passwords."""

    def test_empty_password(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.pbkdf2_sha256.hash("")
        assert passlib_hash.pbkdf2_sha256.verify("", h)
        assert not passlib_hash.pbkdf2_sha256.verify("notempty", h)

    def test_unicode_password(self):
        from hashward.compat import passlib_hash

        pwd = "pässwörd-日本語-🔑"
        h = passlib_hash.pbkdf2_sha256.hash(pwd)
        assert passlib_hash.pbkdf2_sha256.verify(pwd, h)
        assert not passlib_hash.pbkdf2_sha256.verify("ascii", h)

    def test_long_password_sha_crypt(self):
        from hashward.compat import passlib_hash

        # SHA-crypt has no truncation — long passwords should work
        pwd = "A" * 200
        h = passlib_hash.sha256_crypt.hash(pwd)
        assert passlib_hash.sha256_crypt.verify(pwd, h)
        assert not passlib_hash.sha256_crypt.verify("A" * 199, h)

    def test_bytes_password(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.pbkdf2_sha256.hash(b"binary-password")
        assert passlib_hash.pbkdf2_sha256.verify(b"binary-password", h)

    def test_identify_via_handler(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.sha256_crypt.hash("test")
        assert passlib_hash.sha256_crypt.identify(h)
        assert not passlib_hash.md5_crypt.identify(h)

    def test_needs_update_via_handler(self):
        from hashward.compat import passlib_hash

        h = passlib_hash.pbkdf2_sha256.hash("test")
        # Default rounds — should not need update
        assert not passlib_hash.pbkdf2_sha256.needs_update(h)
