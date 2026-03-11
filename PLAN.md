# hashward — Modern Password Hashing for Python

**Package Name:** `hashward` (verified available on PyPI)
**Language:** Python 3.9+
**License:** MIT

---

## Target

**passlib** — the dominant Python password hashing framework, downloaded **27 million times per month**, unmaintained since October 2020.

### Why passlib Must Be Replaced

1. **Abandoned for 5.5 years.** Last release: v1.7.4, Oct 8, 2020. Sole maintainer (Eli Collins) went silent. Promised v1.7.5 never materialized.
2. **Broken on Python 3.13+.** Python 3.13 removed the `crypt` module from stdlib. passlib relies on it for DES, MD5, SHA-256, and SHA-512 crypt schemes — these schemes **crash at runtime** on current Python.
3. **Still supports Python 2.** The codebase carries `six` compatibility shims and Python 2 code paths that no one needs in 2026.
4. **Security-critical package.** Password hashing bugs can compromise authentication for millions of users. An unmaintained security library is an unacceptable risk.
5. **Used by critical infrastructure.** PyPI Warehouse (the Python package index itself), cloud-init (Ubuntu server provisioning), and thousands of authentication systems depend on passlib.
6. **Supply chain risk.** 27M monthly downloads with zero maintenance = a prime target for account takeover or dependency confusion attacks.

### Existing Alternatives (None Are Sufficient)

| Alternative | Monthly Downloads | Drop-in? | Limitations |
|---|---|---|---|
| **libpass** | 253K | Yes (fork) | Just a patched fork of passlib. Inherits all technical debt, Python 2 code, and architectural limitations. |
| **pwdlib** | 1M | No | Only supports bcrypt + argon2. No CryptContext, no hash identification, no legacy scheme support, no migration framework. |
| **bcrypt** / **argon2-cffi** | N/A | No | Low-level single-algorithm libraries. No policy management, no hash identification, no multi-scheme support. |

**No ground-up modern replacement exists.** The community is fragmented across insufficient alternatives, while 27M monthly downloads still flow to the dead original.

---

## Architecture

### Design Principles

1. **Python 3.9+ only** — no Python 2 cruft, full use of modern language features
2. **Zero required dependencies** — pure Python implementations for all hashlib-based schemes (PBKDF2, SHA-crypt, MD5-crypt). Optional dependencies for bcrypt and argon2.
3. **Type hints throughout** — full `py.typed` marker, strict mypy compatibility
4. **passlib-compatible API** — CryptContext and handler interfaces match passlib's API for drop-in migration
5. **Secure by default** — argon2 as default scheme, safe parameter defaults, timing-safe comparisons
6. **No stdlib `crypt` dependency** — pure Python implementations of SHA-256/512-crypt and MD5-crypt, so everything works on Python 3.13+

### Package Structure

```
src/hashward/
├── __init__.py           # Public API: hash, verify, identify, CryptContext
├── _version.py           # Version string
├── context.py            # CryptContext — multi-scheme policy manager
├── identify.py           # Hash identification (detect scheme from hash string)
├── registry.py           # Scheme registry and lazy loading
├── exc.py                # Exceptions
├── _types.py             # Type definitions and protocols
├── _utils.py             # Timing-safe comparison, encoding helpers
├── schemes/
│   ├── __init__.py
│   ├── _base.py          # Base handler protocol and abstract class
│   ├── argon2.py         # Argon2 (id/i/d) — via argon2-cffi (optional dep)
│   ├── bcrypt.py         # bcrypt + bcrypt_sha256 — via bcrypt (optional dep)
│   ├── pbkdf2.py         # PBKDF2-SHA256/512 — pure Python via hashlib
│   ├── scrypt.py         # scrypt — pure Python via hashlib
│   ├── sha_crypt.py      # SHA-256-crypt, SHA-512-crypt — pure Python
│   ├── md5_crypt.py      # MD5-crypt — pure Python
│   ├── des_crypt.py      # DES-crypt — pure Python (legacy, disabled by default)
│   ├── plaintext.py      # Plaintext / ldap_plaintext (for testing/migration)
│   └── django.py         # Django password hashers compatibility
├── compat/
│   ├── __init__.py
│   └── passlib.py        # passlib migration helpers and import aliases
└── py.typed
```

### Key Components

#### 1. Scheme Handlers (`schemes/`)
Each handler implements a common protocol:
- `hash(secret, **settings) → str` — create a new hash
- `verify(secret, hash) → bool` — verify a password against a hash
- `identify(hash) → bool` — check if a hash string belongs to this scheme
- `needs_update(hash) → bool` — check if hash should be re-hashed (outdated params)

#### 2. CryptContext (`context.py`)
The core value proposition — a policy manager for password hashing:
- Configure which schemes are allowed/deprecated/default
- Automatic hash identification and dispatch
- `verify_and_update(secret, hash)` — verify and return new hash if scheme/params are outdated
- Configurable cost parameters, min rounds, max rounds
- INI-file configuration support (passlib compatibility)

#### 3. Hash Identification (`identify.py`)
Detect the hashing scheme from a hash string:
- Prefix-based detection (`$2b$` → bcrypt, `$argon2id$` → argon2, `$5$` → sha256_crypt, etc.)
- Support for all registered schemes
- Extensible registry for custom schemes

#### 4. Compatibility Layer (`compat/`)
- Import aliases matching passlib's module paths
- Migration guide and helper functions
- `hashward.compat.passlib` provides `passlib.context.CryptContext`, `passlib.hash.*` as re-exports

---

## Supported Schemes

### Modern (recommended)
| Scheme | Backend | Default? |
|---|---|---|
| `argon2` (id/i/d) | `argon2-cffi` (optional) | **Yes** |
| `bcrypt` | `bcrypt` (optional) | Supported |
| `bcrypt_sha256` | `bcrypt` (optional) | Supported |
| `scrypt` | `hashlib.scrypt` (stdlib) | Supported |
| `pbkdf2_sha256` | `hashlib.pbkdf2_hmac` (stdlib) | Supported |
| `pbkdf2_sha512` | `hashlib.pbkdf2_hmac` (stdlib) | Supported |

### Legacy (for verification/migration only)
| Scheme | Backend | Notes |
|---|---|---|
| `sha512_crypt` | Pure Python | Common in /etc/shadow |
| `sha256_crypt` | Pure Python | Common in /etc/shadow |
| `md5_crypt` | Pure Python | Legacy, insecure |
| `des_crypt` | Pure Python | Legacy, insecure, disabled by default |
| `plaintext` | N/A | For testing only |

### Django Compatibility
| Scheme | Notes |
|---|---|
| `django_pbkdf2_sha256` | Django's default hasher format |
| `django_bcrypt` | Django bcrypt format |
| `django_argon2` | Django argon2 format |

---

## Implementation Phases

### Phase 1: Core Framework & Modern Schemes
**Scope:** Handler protocol, registry, CryptContext basics, argon2 + bcrypt + pbkdf2 + scrypt schemes.

- Define the handler protocol (`_base.py`)
- Implement argon2, bcrypt, pbkdf2, scrypt scheme handlers
- Build the scheme registry with lazy loading
- Build CryptContext with basic policy (default scheme, verify, hash)
- Hash identification by prefix
- Timing-safe comparison utilities
- Full type hints, `py.typed`
- pyproject.toml, src layout, pytest, MIT license
- Unit tests for all schemes and CryptContext

### Phase 2: Legacy Schemes & Policy Engine
**Scope:** SHA-crypt, MD5-crypt, DES-crypt pure Python implementations. Full CryptContext policy engine.

- Pure Python sha256_crypt / sha512_crypt (no stdlib `crypt` dependency)
- Pure Python md5_crypt
- Pure Python des_crypt (disabled by default)
- CryptContext advanced features: deprecated schemes, `verify_and_update()`, `needs_update()`, configurable rounds/cost
- INI-file configuration support
- Django hasher compatibility

### Phase 3: Compatibility Layer & Migration
**Scope:** passlib import compatibility, migration tools, comprehensive test suite.

- `hashward.compat.passlib` module providing passlib-compatible import paths
- Migration guide documentation
- Test suite verifying hash compatibility with passlib-generated hashes
- Verify against passlib's own test vectors
- Edge case testing (empty passwords, unicode, very long passwords, null bytes)

### Phase 4: Polish & Ship
**Scope:** Documentation, benchmarks, README, PyPI publish.

- Comprehensive README with migration guide from passlib
- API documentation
- Performance benchmarks vs passlib and raw backends
- Security review checklist
- GitHub Actions CI (Python 3.9–3.13+)
- PyPI publish as `hashward`
- Announcement and migration guide blog post

---

## Non-Goals

- **Custom/exotic hash schemes** (e.g., Oracle, MySQL, LDAP) — support only the most common schemes. Users can register custom handlers.
- **Password strength checking** — out of scope, use `zxcvbn` or similar.
- **Key derivation for encryption** — this is a password *hashing* library, not a KDF library.
- **TOTP/HOTP** — out of scope, use `pyotp`.
