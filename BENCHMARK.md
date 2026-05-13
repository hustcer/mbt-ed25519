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

For implementation work, run the same command before and after changes and compare the per-benchmark mean/median values. The current implementation is BigInt + extended Edwards coordinates, so signing and verification are expected to be dominated by scalar multiplication.

## Current Local Baseline

Captured with `moon bench --release` on 2026-05-13:

| Case                                                      | Mean    |
| --------------------------------------------------------- | ------- |
| derive public key from seed                               | 1.56 ms |
| sign license-sized payload                                | 3.21 ms |
| sign license-sized payload with cached SigningKey         | 1.57 ms |
| verify license-sized payload                              | 2.77 ms |
| verify license-sized payload with cached VerifyingKey     | 2.09 ms |
| verify OpenSSL Ed25519 signature                          | 2.74 ms |
| verify OpenSSL Ed25519 signature with cached VerifyingKey | 2.05 ms |

These numbers should be treated as a local baseline, not a portability guarantee. They are useful for comparing optimization branches on the same machine and MoonBit toolchain.

## Optimization History

### Extended Edwards Coordinates

Replaced affine scalar multiplication with extended Edwards coordinates so point addition and doubling no longer perform a field inversion on every step.

Captured with `moon bench --release` on 2026-05-05:

| Case                             | Before    | After   | Latency reduction |
| -------------------------------- | --------- | ------- | ----------------- |
| derive public key from seed      | 185.36 ms | 1.92 ms | 98.96%            |
| sign license-sized payload       | 373.24 ms | 3.89 ms | 98.96%            |
| verify license-sized payload     | 381.89 ms | 4.45 ms | 98.83%            |
| verify OpenSSL Ed25519 signature | 369.25 ms | 4.36 ms | 98.82%            |

### 4-bit Fixed-window Scalar Multiplication

Changed scalar multiplication from bit-by-bit double-and-add to a 4-bit fixed-window method. This keeps the extended-coordinate formulas but reduces point additions during scalar multiplication.

Captured with `moon bench --release` on 2026-05-05:

| Case                             | Before  | After   | Latency reduction |
| -------------------------------- | ------- | ------- | ----------------- |
| derive public key from seed      | 1.92 ms | 1.63 ms | 15.10%            |
| sign license-sized payload       | 3.89 ms | 3.24 ms | 16.71%            |
| verify license-sized payload     | 4.45 ms | 3.74 ms | 15.96%            |
| verify OpenSSL Ed25519 signature | 4.36 ms | 3.74 ms | 14.22%            |

### Cached Basepoint Window Table

Cached the 4-bit window table for the fixed Ed25519 base point. This avoids rebuilding the same table for `a*B`, `r*B`, and `S*B`.

Captured with `moon bench --release` on 2026-05-05:

| Case                             | Before  | After   | Latency reduction |
| -------------------------------- | ------- | ------- | ----------------- |
| derive public key from seed      | 1.63 ms | 1.58 ms | 3.07%             |
| sign license-sized payload       | 3.24 ms | 3.13 ms | 3.40%             |
| verify license-sized payload     | 3.74 ms | 3.69 ms | 1.34%             |
| verify OpenSSL Ed25519 signature | 3.74 ms | 3.64 ms | 2.67%             |

### Cached SigningKey API

Added `SigningKey::from_seed` to cache the expanded scalar, prefix, and public key for repeated signing. This avoids re-expanding the seed and re-deriving the public key for each license payload.

Captured with `moon bench --release` on 2026-05-05:

| Case                       | Ordinary sign | Cached SigningKey sign | Latency reduction |
| -------------------------- | ------------- | ---------------------- | ----------------- |
| sign license-sized payload | 3.14 ms       | 1.58 ms                | 49.68%            |

### 5-bit Scalar Windows

Increased scalar multiplication windows from 4 bits to 5 bits. This uses a larger table but reduces the number of runtime windows and additions.

Captured with `moon bench --release` on 2026-05-05:

| Case                                              | Before  | After   | Latency reduction |
| ------------------------------------------------- | ------- | ------- | ----------------- |
| derive public key from seed                       | 1.58 ms | 1.56 ms | 1.27%             |
| sign license-sized payload                        | 3.14 ms | 3.09 ms | 1.59%             |
| sign license-sized payload with cached SigningKey | 1.58 ms | 1.54 ms | 2.53%             |
| verify license-sized payload                      | 3.75 ms | 3.67 ms | 2.13%             |
| verify OpenSSL Ed25519 signature                  | 3.74 ms | 3.66 ms | 2.14%             |

### Interleaved Double-scalar Verification

Changed verification to compute `S*B - k*A` with an interleaved double-scalar multiplication and compare the result with `R`. This avoids doing two fully separate scalar multiplications during verification.

Captured with `moon bench --release` on 2026-05-05:

| Case                             | Before  | After   | Latency reduction |
| -------------------------------- | ------- | ------- | ----------------- |
| verify license-sized payload     | 3.67 ms | 2.67 ms | 27.25%            |
| verify OpenSSL Ed25519 signature | 3.66 ms | 2.69 ms | 26.50%            |

### Cached VerifyingKey API

Added `VerifyingKey::from_public_key` to cache public-key decoding and the `-A` verification window table. This is useful when the same product public key verifies many license payloads.

Captured with `moon bench --release` on 2026-05-05:

| Case                             | Ordinary verify | Cached VerifyingKey verify | Latency reduction |
| -------------------------------- | --------------- | -------------------------- | ----------------- |
| verify license-sized payload     | 2.66 ms         | 2.01 ms                    | 24.44%            |
| verify OpenSSL Ed25519 signature | 2.66 ms         | 2.00 ms                    | 24.81%            |

### Strict Point Validation and Incremental Hash Input

Added strict rejection for non-canonical point encodings, small-order public
keys, small-order signature `R` points, and non-canonical `S` scalars. Changed
the signing and verification hash inputs to use incremental SHA-512 updates
instead of allocating concatenated temporary arrays.

Captured with `moon bench --release` on 2026-05-13:

| Case                                                      | Mean    |
| --------------------------------------------------------- | ------- |
| derive public key from seed                               | 1.56 ms |
| sign license-sized payload                                | 3.21 ms |
| sign license-sized payload with cached SigningKey         | 1.57 ms |
| verify license-sized payload                              | 2.77 ms |
| verify license-sized payload with cached VerifyingKey     | 2.09 ms |
| verify OpenSSL Ed25519 signature                          | 2.74 ms |
| verify OpenSSL Ed25519 signature with cached VerifyingKey | 2.05 ms |

For full validation after optimization:

```bash
moon fmt
moon check
moon test
moon bench --release
```
