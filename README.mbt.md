# hustcer/ed25519

A pure MoonBit implementation of plain Ed25519 signing and verification.

The package implements deterministic Ed25519 over `BytesView` inputs and `Bytes`
outputs. It is intended for small payloads such as locally signed license data,
plus tests and interoperability checks against RFC 8032 vectors and OpenSSL.

This package is not audited and is not written to be constant-time. Use a mature
audited cryptography library for high-volume, network-facing, or
side-channel-sensitive signing systems.

## Module

Add the module dependency in `moon.mod.json`:

```json
{
  "deps": {
    "hustcer/ed25519": "0.5.0"
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
pub fn derive_public_key(BytesView) -> Bytes raise Ed25519Error
pub fn sign(BytesView, BytesView) -> Bytes raise Ed25519Error
pub fn verify(BytesView, BytesView, BytesView) -> Bool
pub fn verify_result(BytesView, BytesView, BytesView) -> Bool raise Ed25519Error

pub(all) suberror Ed25519Error {
  InvalidSeedLength(got~ : Int)
  InvalidPublicKeyLength(got~ : Int)
  InvalidSignatureLength(got~ : Int)
  PointYOutOfRange
  PointNotOnCurve
  PointNotCanonical
  PublicKeySmallOrder
  SignatureRSmallOrder
  PublicKeyNotPrimeOrder
  SignatureSOutOfRange
} derive(Eq, Debug)
pub impl Show for Ed25519Error

pub struct SigningKey
pub fn SigningKey::from_seed(BytesView) -> SigningKey raise Ed25519Error
pub fn SigningKey::public_key(SigningKey) -> Bytes
pub fn SigningKey::sign(SigningKey, BytesView) -> Bytes
pub fn SigningKey::verifying_key(SigningKey) -> VerifyingKey

pub struct VerifyingKey
pub fn VerifyingKey::from_public_key(BytesView) -> VerifyingKey raise Ed25519Error
pub fn VerifyingKey::public_key(VerifyingKey) -> Bytes
pub fn VerifyingKey::verify(VerifyingKey, BytesView, BytesView) -> Bool
pub fn VerifyingKey::verify_result(
  VerifyingKey,
  BytesView,
  BytesView,
) -> Bool raise Ed25519Error
```

## Data Model

- Private keys are 32-byte Ed25519 seeds.
- Public keys are 32 bytes.
- Signatures are 64 bytes.
- Messages are `BytesView` (`Bytes` is implicitly convertible to `BytesView`).

The implementation validates byte lengths, canonical point encodings,
public-key prime-order subgroup membership, signature `R` prime-order subgroup
membership, and signature `S < L`. Malformed inputs raise `Ed25519Error`, a
checked error whose variants can be pattern matched precisely; its `Show`
instance renders the same human-readable messages as the pre-0.5 string API.

`verify` and `VerifyingKey::verify` return `false` on malformed input or an
invalid signature and never raise. Use `verify_result` or
`VerifyingKey::verify_result` when the caller needs to distinguish malformed
input (raises `Ed25519Error`) from a valid-but-rejected signature (returns
`false`).

## Usage

One-off signing and verification. The fallible functions raise the checked
`Ed25519Error`, so call them from a `raise` context (or handle locally with
`catch`):

```moonbit nocheck
///|
fn issue_and_check_license() -> Bool raise {
  let seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let message : Bytes = b"license"
  let public_key = @ed25519.derive_public_key(seed)
  let signature = @ed25519.sign(seed, message)
  @ed25519.verify(public_key, message, signature)
}
```

To handle a malformed input precisely, match the error variants:

```moonbit nocheck
///|
fn check_strict(public_key : Bytes, message : Bytes, sig : Bytes) -> Bool {
  @ed25519.verify_result(public_key, message, sig) catch {
    @ed25519.InvalidPublicKeyLength(got~) => {
      println("bad public key length: \{got}")
      false
    }
    err => {
      println("malformed input: \{err}")
      false
    }
  }
}
```

For repeated signing with the same seed, create a `SigningKey` once. It caches
the expanded scalar, prefix, and derived public key:

```moonbit nocheck
///|
let signing_key = @ed25519.SigningKey::from_seed(seed)

///|
let public_key = signing_key.public_key()

///|
let signature = signing_key.sign(message)
```

For repeated verification with the same public key, create a `VerifyingKey`
once. It caches the decoded public key and verification table:

```moonbit nocheck
///|
let verifying_key = @ed25519.VerifyingKey::from_public_key(public_key)

///|
let ok = verifying_key.verify(message, signature)
```

When you hold the `SigningKey`, derive its `VerifyingKey` directly instead of
re-decoding the encoded public key. The signing key already validated its own
public point, so this constructor is infallible and skips the point decode and
prime-order subgroup check:

```moonbit nocheck
///|
let verifying_key = signing_key.verifying_key()
```

## Implementation Notes

This is a plain Ed25519 implementation using SHA-512 from `Tigls/mb-hash`.
It does not expose Ed25519ph or Ed25519ctx variants.

Verification is intentionally strict: non-canonical point encodings,
public keys outside the prime-order subgroup, signature `R` points outside the
prime-order subgroup, and non-canonical `S` scalars are rejected as malformed
inputs.

The curve arithmetic uses MoonBit `BigInt`, extended Edwards coordinates,
fixed-length 5-bit scalar windows, a cached basepoint table, and an interleaved
double-scalar verification path. SHA-512 inputs are fed in bounded chunks instead
of first materializing `prefix || message` or `R || A || message` as one large
array. The signing and key-derivation path scans the full basepoint table for
each scalar window instead of indexing it directly by a secret digit, but this
package is still not constant-time because `BigInt` arithmetic, branching,
allocation, and verification table access remain data-dependent. The cached key
types avoid repeated setup work when signing or verifying multiple messages with
the same key material.

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

The script runs seven scenario groups against a fresh OpenSSL Ed25519 install
and the MoonBit interop binary in `cmd/openssl-interop`:

1. **Length matrix** — signs and cross-verifies messages of 1, 2, 32, 64, 111,
   112, 119, 120, 127, 128, 129, 200, 256, and 1024 bytes against one fresh key.
   Sizes 111/112/119/120/127/128/129 straddle the SHA-512 block + padding
   boundary; sizes ≥ 256 cover every byte value including NUL and high-bit.
2. **Multi-iteration** — repeats the basic round-trip with a freshly generated
   OpenSSL key on each iteration (default 4, controlled by `--iterations N`).
3. **Tamper rejection** — for one signed message, flips one byte in the
   message, the signature `R`, and the signature `S`, and asserts that both
   OpenSSL `pkeyutl -verify` and MoonBit `verify` reject each variant.
4. **Public-key tamper rejection** — flips one byte of the verifying public
   key at positions 0 and 31, wraps the result into a fresh SPKI DER, and
   asserts both sides reject the legitimate signature under the tampered
   pubkey (whether decode fails or the curve math fails downstream).
5. **Reverse pubkey load** — wraps the MoonBit-derived 32-byte public key into
   an Ed25519 SubjectPublicKeyInfo DER, loads it with OpenSSL, and verifies
   the MoonBit signature using that reconstructed PEM. Proves MoonBit pubkey
   bytes are independently OpenSSL-loadable.
6. **External-seed injection** — builds an OpenSSL DER private key from an
   RFC 8032 vector-1 seed, derives the public key via OpenSSL, asserts it
   matches the RFC vector, and asserts MoonBit produces the RFC vector-1
   signature for the empty message. Anchors the seed → key → signature
   pipeline at known coordinates. (The empty-message signing happens through
   MoonBit because `openssl pkeyutl -sign -rawin` refuses 0-byte input.)
7. **Non-prime-order public key** — verifies a legitimate OpenSSL signature
   against the cofactor-mixed public key `B + 4-torsion` (`5252cc0a…65ea`).
   MoonBit rejects the key as malformed (`public key is not in the prime-order
subgroup`) before signature math; OpenSSL loads the SPKI successfully and
   only fails at `pkeyutl -verify`.

Pass `--keep-temp` to retain the working directory for inspection.

## License

Apache-2.0. See `LICENSE`.
