# Benchmarking

Use MoonBit's built-in benchmark runner from this package root:

```bash
moon bench --release
```

The benchmark suite covers:

- deriving a public key from a 32-byte seed
- signing a compact S8FY-style license payload
- verifying that license payload
- verifying an OpenSSL-generated Ed25519 signature

For implementation work, run the same command before and after changes and compare the per-benchmark mean/median values. The current implementation is BigInt + affine Edwards coordinates, so signing and verification are expected to be dominated by scalar multiplication and field inversion.

## Current Local Baseline

Captured with `moon bench --release` on 2026-05-05:

| Case | Mean |
| ---- | ---- |
| derive public key from seed | 185.36 ms |
| sign license-sized payload | 373.24 ms |
| verify license-sized payload | 381.89 ms |
| verify OpenSSL Ed25519 signature | 369.25 ms |

These numbers should be treated as a local baseline, not a portability guarantee. They are useful for comparing optimization branches on the same machine and MoonBit toolchain.

## Optimization History

### Extended Edwards Coordinates

Replaced affine scalar multiplication with extended Edwards coordinates so point addition and doubling no longer perform a field inversion on every step.

Captured with `moon bench --release` on 2026-05-05:

| Case | Before | After | Latency reduction |
| ---- | ------ | ----- | ----------------- |
| derive public key from seed | 185.36 ms | 1.92 ms | 98.96% |
| sign license-sized payload | 373.24 ms | 3.89 ms | 98.96% |
| verify license-sized payload | 381.89 ms | 4.45 ms | 98.83% |
| verify OpenSSL Ed25519 signature | 369.25 ms | 4.36 ms | 98.82% |

### 4-bit Fixed-window Scalar Multiplication

Changed scalar multiplication from bit-by-bit double-and-add to a 4-bit fixed-window method. This keeps the extended-coordinate formulas but reduces point additions during scalar multiplication.

Captured with `moon bench --release` on 2026-05-05:

| Case | Before | After | Latency reduction |
| ---- | ------ | ----- | ----------------- |
| derive public key from seed | 1.92 ms | 1.63 ms | 15.10% |
| sign license-sized payload | 3.89 ms | 3.24 ms | 16.71% |
| verify license-sized payload | 4.45 ms | 3.74 ms | 15.96% |
| verify OpenSSL Ed25519 signature | 4.36 ms | 3.74 ms | 14.22% |

For full validation after optimization:

```bash
moon fmt
moon check
moon test
moon bench --release
```
