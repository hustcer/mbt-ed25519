# CHANGELOG

All notable changes to this project will be documented in this file.

## v0.2.0 - 2026-05-15

### Breaking Changes

- All public functions (`sign`, `verify`, `verify_result`, `derive_public_key`,
  `SigningKey::from_seed`, `SigningKey::sign`, `SigningKey::public_key`,
  `VerifyingKey::from_public_key`, `VerifyingKey::public_key`,
  `VerifyingKey::verify`, `VerifyingKey::verify_result`) now accept
  `BytesView` for input and return `Bytes` instead of `Array[UInt]`.

### Security

- Reject non-canonical and small-order points during point decoding.
- Return an error when the signature scalar `s` is non-canonical (`s >= L`).
- Verify the curve equation explicitly in `decode_point`.
- Use a fixed-iteration loop count in scalar multiplication, removing
  data-dependent branches (affects both signing and verification).
- Abort on overflow in `bigint_to_le_bytes` when the value exceeds the
  expected byte length, preventing silent byte truncation.

### Performance

- Hash Ed25519 inputs incrementally using `Sha512::update` instead of
  concatenating all bytes into one buffer before hashing.
- Replace the manual little-endian byte loop with `BigInt::from_octets`.
- Build the SHA-512 input as a single `Array[UInt]` per call.

### Tests

- Add blackbox tests for malformed Ed25519 inputs (bad public key, bad
  signature, flipped bits).
- Add tests for `s = L - 1` (largest canonical scalar) and multi-block
  SHA-512 messages.
- Add whitebox tests for `scalar_window5_digits` (zero input, boundary
  values, roundtrip on representative scalars).

### Tools

- Expand `tools/openssl-interop.nu` with six scenario groups: length matrix
  (14 message sizes), multi-iteration key generation, tamper rejection
  (message / R / S), public-key tamper rejection, reverse pubkey load, and
  external-seed injection from RFC 8032 test vector 1.
- Replace heuristic DER byte extraction with full-prefix-and-length-validated
  extraction for both the private seed and public key in the interop script.

### Docs

- Document strict verification behaviour and add benchmark baseline for v0.2.0.

### Chores

- Remove redundant `[:]` `Bytes`→`BytesView` conversions.
- Rename `Err` pattern bindings to avoid shadowing the `message` parameter.
- Remove redundant constructor annotations.
- Switch tests to use `@test.assert_eq` from `moonbitlang/core/test`.
