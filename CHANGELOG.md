# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-12

### Added

**Core framework**
- `SchemeRegistry` with lazy loading for all built-in schemes
- `CryptContext` policy manager: `hash()`, `verify()`, `identify()`, `needs_update()`, `verify_and_update()`
- Hash identification by prefix for all supported schemes
- Module-level convenience functions (`hashward.hash`, `hashward.verify`, `hashward.identify`)
- Full type hints throughout; `py.typed` marker for PEP 561 compatibility

**Modern scheme handlers** (recommended for new projects)
- `argon2` (id/i/d variants) — via `argon2-cffi` optional dependency
- `bcrypt` and `bcrypt_sha256` — via `bcrypt` optional dependency
- `pbkdf2_sha256` and `pbkdf2_sha512` — pure Python via `hashlib`
- `scrypt` — pure Python via `hashlib`

**Legacy scheme handlers** (verification and migration only)
- `sha512_crypt` (`$6$`) — pure Python, Python 3.13+ safe (no `crypt` stdlib dependency)
- `sha256_crypt` (`$5$`) — pure Python, Python 3.13+ safe
- `md5_crypt` (`$1$`) — pure Python
- `des_crypt` — pure Python, always reports `needs_update=True`
- `plaintext` — for testing/migration only

**Django compatibility**
- `django_pbkdf2_sha256`, `django_bcrypt`, `django_bcrypt_sha256`, `django_argon2`, `django_scrypt` handlers

**passlib compatibility layer**
- `hashward.compat.passlib` providing `CryptContext` re-export
- `hashward.compat.passlib_hash` with lazy handler singletons for all schemes (drop-in for `passlib.hash.*`)

**Advanced CryptContext features**
- Per-scheme settings via `argon2__time_cost=3` syntax
- `using()` / `copy()` for config derivation
- `truncate_error` for bcrypt 72-byte limit enforcement
- `min_verify_time` for timing normalization
- INI config serialization: `to_string()` / `from_string()`
- Deprecated schemes with automatic migration via `verify_and_update()`

**Tooling**
- GitHub Actions CI matrix across Python 3.9–3.13 (test, lint, type-check, build)
- Performance benchmarks for all 9 schemes (`benchmarks/bench_hashing.py`)
- Comprehensive test suite: 296 tests

### Fixed
- SHA-256-crypt and SHA-512-crypt final byte encoding (Drepper spec compliance)
- MD5-crypt: all 5 encoding groups now processed correctly
- DES-crypt: S-box 8 data, key packing, and output encoding corrected
- `bcrypt_sha256` format compatibility with passlib v1 and v2 hash formats
- SHA-crypt salt truncation to 16 chars per spec; invalid salt character rejection
- `Argon2Handler` now passes `bytes` directly to `argon2-cffi` (fixes non-UTF-8 passwords)
- `CryptContext.identify()` now scoped to configured schemes only
- `CryptContext.from_string()` uses `RawConfigParser` (prevents `%(key)s` interpolation)
- `DjangoArgon2Handler.needs_update()` now delegates to `argon2-cffi` `check_needs_rehash()`
- `DjangoArgon2Handler.verify()` catches `InvalidHashError` on malformed hashes
- `ScryptHandler.verify()` catches `ValueError` on invalid scrypt parameters
- `verify()` and `identify()` return `False`/`None` on non-string hash input (no crash)
- Django scheme aliases in passlib compat module (`django_pbkdf2_sha256`, etc.)
