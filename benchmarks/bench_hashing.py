"""Performance benchmarks for hashward password hashing schemes.

Measures hash and verify times for all supported schemes with their
default parameters. Run with:

    python benchmarks/bench_hashing.py

Results are printed as a formatted table.
"""

from __future__ import annotations

import statistics
import sys
import time


def _bench(func, iterations: int = 5) -> dict[str, float]:
    """Benchmark a function, returning timing stats in milliseconds."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)
    return {
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
    }


def bench_scheme(scheme_name: str, handler, password: str = "correct horse battery staple") -> dict:
    """Benchmark hash and verify for a single scheme."""
    # Hash benchmark
    hash_stats = _bench(lambda: handler.hash(password), iterations=3)

    # Generate a hash for verify benchmark
    hashed = handler.hash(password)
    verify_stats = _bench(lambda: handler.verify(password, hashed), iterations=3)

    return {
        "scheme": scheme_name,
        "hash": hash_stats,
        "verify": verify_stats,
    }


def run_benchmarks() -> list[dict]:
    """Run benchmarks for all available schemes."""
    from hashward.registry import DEFAULT_REGISTRY

    # Schemes to benchmark (ordered by category)
    modern_schemes = ["argon2", "bcrypt", "bcrypt_sha256", "scrypt", "pbkdf2_sha256", "pbkdf2_sha512"]
    legacy_schemes = ["sha256_crypt", "sha512_crypt", "md5_crypt"]

    results = []

    for scheme_name in modern_schemes + legacy_schemes:
        try:
            handler = DEFAULT_REGISTRY.get(scheme_name)
            result = bench_scheme(scheme_name, handler)
            results.append(result)
        except Exception as e:
            results.append({
                "scheme": scheme_name,
                "error": str(e),
            })

    return results


def print_results(results: list[dict]) -> None:
    """Print benchmark results as a formatted table."""
    header = f"{'Scheme':<20} {'Hash (ms)':<14} {'Verify (ms)':<14} {'Notes'}"
    print()
    print("=" * 70)
    print("hashward Benchmark Results")
    print("=" * 70)
    print()
    print(header)
    print("-" * 70)

    for r in results:
        if "error" in r:
            print(f"{r['scheme']:<20} {'SKIPPED':<14} {'SKIPPED':<14} {r['error']}")
            continue

        hash_ms = r["hash"]["mean_ms"]
        verify_ms = r["verify"]["mean_ms"]

        # Categorize speed
        if hash_ms < 10:
            note = "fast (legacy)"
        elif hash_ms < 100:
            note = ""
        elif hash_ms < 500:
            note = "moderate"
        else:
            note = "memory-hard"

        print(f"{r['scheme']:<20} {hash_ms:>10.1f}    {verify_ms:>10.1f}    {note}")

    print()
    print("Lower times = faster (but modern schemes are intentionally slow)")
    print("Benchmarked with default parameters on this machine.")
    print()


def main() -> int:
    """Run benchmarks and print results."""
    print("Running hashward benchmarks...")
    print(f"Python {sys.version}")
    print()

    results = run_benchmarks()
    print_results(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
