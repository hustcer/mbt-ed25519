# hustcer/ed25519

A pure MoonBit implementation of plain Ed25519 signing and verification.

The package implements deterministic Ed25519 over `Array[UInt]` byte arrays. It
is intended for small payloads such as locally signed license data, plus tests
and interoperability checks against RFC 8032 vectors and OpenSSL.

This package is not audited and is not written to be constant-time. Use a mature
audited cryptography library for high-volume, network-facing, or
side-channel-sensitive signing systems.

## Module

Add the module dependency in `moon.mod.json`:

```json
{
  "deps": {
    "hustcer/ed25519": "0.2.0"
  }
}
```

Import it from `moon.pkg` with an alias:

```moonbit nocheck
import {
  "hustcer/ed25519" @ed25519,
}
```

This repository itself depends on `Tigls/mb-hash` for SHA-512.

## API

The public API is generated in `pkg.generated.mbti` and currently consists of:

```moonbit nocheck
pub fn derive_public_key(BytesView) -> Result[Bytes, String]
pub fn sign(BytesView, BytesView) -> Result[Bytes, String]
pub fn verify(BytesView, BytesView, BytesView) -> Bool
pub fn verify_result(BytesView, BytesView, BytesView) -> Result[Bool, String]

pub struct SigningKey
pub fn SigningKey::from_seed(BytesView) -> Result[SigningKey, String]
pub fn SigningKey::public_key(SigningKey) -> Bytes
pub fn SigningKey::sign(SigningKey, BytesView) -> Bytes

pub struct VerifyingKey
pub fn VerifyingKey::from_public_key(BytesView) -> Result[VerifyingKey, String]
pub fn VerifyingKey::public_key(VerifyingKey) -> Bytes
pub fn VerifyingKey::verify(VerifyingKey, BytesView, BytesView) -> Bool
pub fn VerifyingKey::verify_result(
  VerifyingKey,
  BytesView,
  BytesView,
) -> Result[Bool, String]
```

## Data Model

- Private keys are 32-byte Ed25519 seeds.
- Public keys are 32 bytes.
- Signatures are 64 bytes.
- Messages are `BytesView` (`Bytes` is implicitly convertible to `BytesView`).

The implementation validates byte lengths, canonical point encodings,
public-key subgroup membership, signature `R` subgroup membership, and
signature `S < L`. The `Result` returning functions report malformed inputs
as `Err(String)`.

`verify` and `VerifyingKey::verify` return `false` on malformed input or an
invalid signature. Use `verify_result` or `VerifyingKey::verify_result` when the
caller needs to distinguish malformed input from a valid-but-rejected signature.

## Usage

One-off signing and verification:

```moonbit nocheck
///|
let seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"

///|
let message : Bytes = b"license"

///|
let public_key = @ed25519.derive_public_key(seed).unwrap()

///|
let signature = @ed25519.sign(seed, message).unwrap()

///|
let ok = @ed25519.verify(public_key, message, signature)
```

For repeated signing with the same seed, create a `SigningKey` once. It caches
the expanded scalar, prefix, and derived public key:

```moonbit nocheck
///|
let signing_key = @ed25519.SigningKey::from_seed(seed).unwrap()

///|
let public_key = signing_key.public_key()

///|
let signature = signing_key.sign(message)
```

For repeated verification with the same public key, create a `VerifyingKey`
once. It caches the decoded public key and verification table:

```moonbit nocheck
///|
let verifying_key = @ed25519.VerifyingKey::from_public_key(public_key).unwrap()

///|
let ok = verifying_key.verify(message, signature)
```

## Implementation Notes

This is a plain Ed25519 implementation using SHA-512 from `Tigls/mb-hash`.
It does not expose Ed25519ph or Ed25519ctx variants.

Verification is intentionally strict: non-canonical point encodings,
small-order public keys, small-order signature `R` points, and non-canonical
`S` scalars are rejected as malformed inputs.

The curve arithmetic uses MoonBit `BigInt`, extended Edwards coordinates,
fixed-length 5-bit scalar windows, a cached basepoint table, and an interleaved
double-scalar verification path. The fixed scalar schedule removes window-length
and zero-digit branches, but this package is still not constant-time because
`BigInt` arithmetic and table access remain data-dependent. The cached key types
avoid repeated setup work when signing or verifying multiple messages with the
same key material.

## Development

Useful commands from the repository root:

```bash
moon fmt
moon check
moon test
moon info
```

`moon info` regenerates `pkg.generated.mbti`, which is the easiest way to review
public API changes.

Run benchmarks with:

```bash
moon bench --release
```

See `BENCHMARK.md` for the benchmark cases and local historical measurements.
Benchmark numbers are local measurements, not performance guarantees.

## OpenSSL Interop Check

The interop check requires Nushell and OpenSSL:

```bash
nu tools/openssl-interop.nu
```

The script generates an OpenSSL Ed25519 key, extracts the 32-byte seed, signs a
payload with OpenSSL and this package, compares public keys and signatures, and
verifies signatures in both directions.

## License

Apache-2.0. See `LICENSE`.
