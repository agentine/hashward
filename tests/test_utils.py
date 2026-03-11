"""Tests for hashward._utils."""

from hashward._utils import ab64_decode, ab64_encode, b64_decode, b64_encode, consteq, generate_salt, to_bytes


class TestConsteq:
    def test_equal_strings(self):
        assert consteq("hello", "hello") is True

    def test_unequal_strings(self):
        assert consteq("hello", "world") is False

    def test_equal_bytes(self):
        assert consteq(b"hello", b"hello") is True

    def test_unequal_bytes(self):
        assert consteq(b"hello", b"world") is False

    def test_mixed_types(self):
        assert consteq("hello", b"hello") is True

    def test_empty(self):
        assert consteq("", "") is True
        assert consteq(b"", b"") is True


class TestToBytes:
    def test_str_input(self):
        assert to_bytes("hello") == b"hello"

    def test_bytes_input(self):
        assert to_bytes(b"hello") == b"hello"

    def test_unicode(self):
        assert to_bytes("\u00e9") == b"\xc3\xa9"


class TestB64:
    def test_roundtrip(self):
        data = b"hello world"
        assert b64_decode(b64_encode(data)) == data

    def test_empty(self):
        assert b64_decode(b64_encode(b"")) == b""

    def test_binary(self):
        data = bytes(range(256))
        assert b64_decode(b64_encode(data)) == data


class TestAb64:
    def test_roundtrip(self):
        data = b"hello world"
        assert ab64_decode(ab64_encode(data)) == data

    def test_binary(self):
        data = bytes(range(256))
        assert ab64_decode(ab64_encode(data)) == data


class TestGenerateSalt:
    def test_default_size(self):
        salt = generate_salt()
        assert len(salt) == 16

    def test_custom_size(self):
        salt = generate_salt(32)
        assert len(salt) == 32

    def test_unique(self):
        assert generate_salt() != generate_salt()
