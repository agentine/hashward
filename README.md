# hashward

**Modern password hashing for Python.** A drop-in replacement for [passlib](https://foss.heptapod.net/python-libs/passlib/-/wikis/home), which has been unmaintained since 2020 and is broken on Python 3.13+.

[![CI](https://github.com/agentine/hashward/actions/workflows/ci.yml/badge.svg)](https://github.com/agentine/hashward/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/hashward.svg)](https://pypi.org/project/hashward/)
[![Python versions](https://img.shields.io/pypi/pyversions/hashward.svg)](https://pypi.org/project/hashward/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why hashward?

- **passlib is dead.** Last release was October 2020. It crashes on Python 3.13+ due to the removed `crypt` module.
- **Zero required dependencies.** Pure Python implementations for all hashlib-based schemes. Optional deps for argon2 and bcrypt.
- **Python 3.9+ only.** No Python 2 baggage. Full type hints with `py.typed` marker.
- **passlib-compatible API.** `CryptContext`, hash identification, and `verify_and_update()` all work the same way.
- **Secure defaults.** Argon2id as the default scheme with safe parameter defaults and timing-safe comparisons.

## Installation

```bash
pip install hashward
```

With argon2 support (recommended):
```bash
pip install hashward[argon2]
```

With bcrypt support:
```bash
pip install hashward[bcrypt]
```

With everything:
```bash
pip install hashward[all]
```

## Quick Start

### Simple hashing and verification

```python
import hashward

# Hash a password (uses argon2id by default)
hashed = hashward.hash("my secret password")
# '$argon2id$v=19$m=65536,t=2,p=2$...'

# Verify a password
hashward.verify("my secret password", hashed)   # True
hashward.verify("wrong password", hashed)        # False

# Use a specific scheme
hashed = hashward.hash("my secret password", scheme="bcrypt")
# '$2b$12$...'
```

### CryptContext for policy management

```python
from hashward import CryptContext

# Create a context with your preferred schemes
ctx = CryptContext(
    schemes=["argon2", "bcrypt", "pbkdf2_sha256"],
    default="argon2",
    deprecated=["pbkdf2_sha256"],
    argon2__time_cost=3,
    argon2__memory_cost=65536,
)

# Hash and verify
hashed = ctx.hash("password")
assert ctx.verify("password", hashed)

# Automatic scheme identification
ctx.identify(hashed)  # "argon2"

# Check if a hash needs upgrading (deprecated scheme or outdated params)
ctx.needs_update(hashed)  # False (it's current)

# Verify and get a new hash if the old one needs upgrading
valid, new_hash = ctx.verify_and_update("password", old_bcrypt_hash)
if valid and new_hash:
    # Save new_hash to your database — it's been upgraded to argon2
    save_to_db(new_hash)
```

### Hash identification

```python
from hashward import identify

identify("$argon2id$v=19$m=65536,t=2,p=2$...")  # "argon2"
identify("$2b$12$...")                            # "bcrypt"
identify("$6$rounds=656000$...")                  # "sha512_crypt"
identify("$1$...")                                # "md5_crypt"
identify("pbkdf2_sha256$600000$...")              # "django_pbkdf2_sha256"
```

### INI configuration (passlib-compatible)

```python
from hashward import CryptContext

# Load from INI-format string
config = """
[hashward]
schemes = argon2, bcrypt, pbkdf2_sha256
default = argon2
deprecated = pbkdf2_sha256
argon2__time_cost = 3
argon2__memory_cost = 65536
"""
ctx = CryptContext.from_string(config)

# Serialize back
print(ctx.to_string())
```

## Supported Schemes

### Modern (recommended for new hashes)

| Scheme | Backend | Notes |
|---|---|---|
| `argon2` | [argon2-cffi](https://pypi.org/project/argon2-cffi/) | **Default.** Argon2id, memory-hard. Requires `pip install hashward[argon2]`. |
| `bcrypt` | [bcrypt](https://pypi.org/project/bcrypt/) | Industry standard. Requires `pip install hashward[bcrypt]`. |
| `bcrypt_sha256` | [bcrypt](https://pypi.org/project/bcrypt/) | Bcrypt with SHA-256 pre-hash (no 72-byte limit). |
| `scrypt` | `hashlib.scrypt` (stdlib) | Memory-hard. No extra dependencies. |
| `pbkdf2_sha256` | `hashlib.pbkdf2_hmac` (stdlib) | NIST-approved. No extra dependencies. |
| `pbkdf2_sha512` | `hashlib.pbkdf2_hmac` (stdlib) | NIST-approved. No extra dependencies. |

### Legacy (verification and migration only)

| Scheme | Notes |
|---|---|
| `sha512_crypt` | Common in `/etc/shadow`. Pure Python, no `crypt` module needed. |
| `sha256_crypt` | Common in `/etc/shadow`. Pure Python, no `crypt` module needed. |
| `md5_crypt` | Insecure. Always reports `needs_update`. |
| `des_crypt` | Insecure. Disabled by default. |

### Django compatibility

| Scheme | Notes |
|---|---|
| `django_pbkdf2_sha256` | Django's default hasher format. |
| `django_bcrypt` | Django bcrypt format. |
| `django_bcrypt_sha256` | Django bcrypt+SHA-256 format. |
| `django_argon2` | Django argon2 format. |
| `django_scrypt` | Django scrypt format. |

## Migrating from passlib

hashward provides a compatibility layer for gradual migration.

### Step 1: Replace imports

```python
# Before (passlib):
from passlib.context import CryptContext

# After (hashward — direct):
from hashward import CryptContext

# Or use the compat shim for minimal changes:
from hashward.compat.passlib import CryptContext
```

### Step 2: Update context configuration

```python
# passlib config:
ctx = CryptContext(schemes=["argon2", "bcrypt", "pbkdf2_sha256"])

# hashward config (identical API):
ctx = CryptContext(schemes=["argon2", "bcrypt", "pbkdf2_sha256"])
```

### Step 3: Verify existing hashes still work

hashward can verify hashes generated by passlib. All passlib hash formats are recognized, including `bcrypt_sha256` v1 and v2 formats.

```python
from hashward import CryptContext

ctx = CryptContext(schemes=["argon2", "bcrypt", "pbkdf2_sha256"], deprecated=["pbkdf2_sha256"])

# Verify a passlib-generated hash
old_hash = "$pbkdf2-sha256$29000$..."  # generated by passlib
valid = ctx.verify("password", old_hash)

# Automatically upgrade old hashes
valid, new_hash = ctx.verify_and_update("password", old_hash)
if valid and new_hash:
    # new_hash is argon2id — save it
    save_to_db(new_hash)
```

## API Reference

### Module-level functions

#### `hashward.hash(secret, scheme="argon2")`
Hash a password using the specified scheme (default: argon2).

#### `hashward.verify(secret, hash_string)`
Verify a password against a hash string. Automatically identifies the scheme.

#### `hashward.identify(hash_string)`
Detect the hashing scheme from a hash string. Returns the scheme name or `None`.

### CryptContext

#### `CryptContext(schemes, default, deprecated, **settings)`
Create a policy manager for password hashing.

- `schemes` — list of allowed scheme names
- `default` — scheme to use for new hashes
- `deprecated` — list of schemes that trigger `needs_update()`
- `**settings` — per-scheme settings using `scheme__param=value` syntax

#### `ctx.hash(secret, scheme=None, **settings)`
Hash a password. Uses the default scheme unless overridden.

#### `ctx.verify(secret, hash)`
Verify a password against a hash. Returns `False` for unrecognized hashes.

#### `ctx.identify(hash)`
Identify the scheme of a hash string. Only returns schemes configured in this context.

#### `ctx.needs_update(hash)`
Check if a hash needs re-hashing (deprecated scheme or outdated parameters).

#### `ctx.verify_and_update(secret, hash)`
Verify and return `(valid, new_hash)`. `new_hash` is `None` if no update is needed.

#### `ctx.using(**overrides)`
Return a new CryptContext with overridden settings.

#### `ctx.to_string()` / `CryptContext.from_string(ini_str)`
Serialize to / deserialize from INI-format configuration strings.

## Security Considerations

- **Default scheme is argon2id** with memory-hard parameters (64 MiB, 2 iterations, 2 threads).
- **Timing-safe comparisons** via `hmac.compare_digest` for all hash verification.
- **No `crypt` module dependency.** All legacy schemes (SHA-crypt, MD5-crypt, DES-crypt) use pure Python implementations.
- **DES-crypt is disabled by default.** It must be explicitly registered to use.
- **bcrypt 72-byte limit** is handled: passwords are silently truncated. Use `bcrypt_sha256` or `truncate_error=True` in CryptContext for explicit control.

## Development

```bash
# Clone and set up
git clone https://github.com/agentine/hashward.git
cd hashward
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run benchmarks
python benchmarks/bench_hashing.py
```

## License

MIT
