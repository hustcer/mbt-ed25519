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

For full validation after optimization:

```bash
moon fmt
moon check
moon test
moon bench --release
```
