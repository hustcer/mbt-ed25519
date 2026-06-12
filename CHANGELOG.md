# CHANGELOG

All notable changes to this project will be documented in this file.

## v0.5.0 - 2026-06-12

### Breaking Changes

- Replace the public `Result[_, String]` error API with checked MoonBit errors.
  Fallible public functions now return their success value directly and declare
  `raise Ed25519Error`:
  - `derive_public_key(seed)` now returns `Bytes raise Ed25519Error`.
  - `sign(seed, message)` now returns `Bytes raise Ed25519Error`.
  - `SigningKey::from_seed(seed)` now returns `SigningKey raise Ed25519Error`.
  - `VerifyingKey::from_public_key(public_key)` now returns
    `VerifyingKey raise Ed25519Error`.
  - `verify_result(public_key, message, signature)` now returns
    `Bool raise Ed25519Error`.
  - `VerifyingKey::verify_result(message, signature)` now returns
    `Bool raise Ed25519Error`.
- The boolean convenience wrappers are intentionally unchanged:
  `verify(...) -> Bool` and `VerifyingKey::verify(...) -> Bool` still never
  raise and still collapse malformed input to `false`.

### Migration Guide

- Replace success-path unwrapping with direct calls inside a `raise` context.
  For example, change `@ed25519.sign(seed, message).unwrap()` to
  `@ed25519.sign(seed, message)` and make the containing function declare
  `raise` or `raise @ed25519.Ed25519Error`.
- Replace `match`/`if` logic over `Ok(value)` and `Err(message)` with
  `try ... catch ... noraise` or expression-level `catch`.
  - Old invalid-input handling matched `Err("signature must be 64 bytes")`.
  - New invalid-input handling catches
    `@ed25519.InvalidSignatureLength(got=...)`.
- Replace `Ok(false)` checks from `verify_result` with plain `false` checks.
  A malformed input now raises; a well-formed but invalid signature still
  returns `false`.
- Code that only calls `verify` or `VerifyingKey::verify` does not need to
  change unless it also constructs a cached `VerifyingKey` with
  `VerifyingKey::from_public_key`.
- For one-off command-line tools or tests where malformed inputs should abort,
  `try! @ed25519.sign(...)` remains a possible local adaptation, but library
  code should usually propagate with `raise` or handle with `catch`.

### Added

- Add public checked error type `Ed25519Error` with structured variants for all
  malformed-input cases:
  - `InvalidSeedLength(got~ : Int)`
  - `InvalidPublicKeyLength(got~ : Int)`
  - `InvalidSignatureLength(got~ : Int)`
  - `PointYOutOfRange`
  - `PointNotOnCurve`
  - `PointNotCanonical`
  - `PublicKeySmallOrder`
  - `SignatureRSmallOrder`
  - `PublicKeyNotPrimeOrder`
  - `SignatureSOutOfRange`
- `Ed25519Error` derives `Eq` and `Debug`, so callers and tests can match or
  assert exact variants instead of comparing strings.
- `Ed25519Error` implements `Show` using the same human-readable messages as
  the previous string API. Existing logs and interop output can remain stable
  when callers render the error with `to_string()`.

### Refactor

- Propagate internal validation failures with `raise Ed25519Error` instead of
  manually threading `Result` values through point decoding, key expansion, and
  strict verification helpers.
- Treat the internal `decode_point` length check as an internal contract abort;
  public callers still pre-validate seed, public-key, and signature lengths and
  raise the structured public variants.
- Update the OpenSSL interop command to accept raising verification closures
  while keeping its printed error detail strings byte-compatible.

### Tests and Docs

- Rewrite error-path tests to assert exact `Ed25519Error` variants via
  `try`/`catch`.
- Add coverage pinning all `Ed25519Error` `Show` messages.
- Update README examples to show raise-context usage, catch-based precise
  matching, and the new public API surface.
- Regenerate `pkg.generated.mbti` for the new public API.

## v0.4.0 - 2026-06-12

### Added

- Add `SigningKey::verifying_key`, an infallible way to derive a cached `VerifyingKey` directly from a `SigningKey` without re-decoding the encoded public key.

### Performance

- Decode Ed25519 points with the RFC 8032 single-exponentiation square-root path.
- Reuse the negated public-key window table for the prime-order subgroup check.
- Reduce modular reductions in point addition/doubling and reuse the SHA-512 byte conversion buffer across chunks.

### Reliability and Tests

- Guard windowed scalar digit splitting against negative and over-255-bit scalars.
- Share public-key length validation between one-shot verification and cached `VerifyingKey` construction.
- Add coverage for `SigningKey::verifying_key`, malformed point encodings, scalar bounds, lazy point arithmetic, and SHA-512 buffer reuse.

## v0.3.0 - 2026-05-25

### Behavior Changes

- `verify_result` returns `Ok(false)` instead of `Err("signature R is not in the prime-order subgroup")` for cofactor-mixed signature `R`. The check now runs after the main verification equation as defense-in-depth. Callers matching the exact error string must update; boolean callers are unaffected.

### Performance

- Defer the `R` prime-order subgroup check until after the main verification equation. Cached-`VerifyingKey` rejection of a tampered signature drops from ~3.5 ms to ~2.0 ms (`moon bench --release`); valid-signature verification is unchanged.
- Skip the first iteration's no-op doublings of identity in `extended_mul_with_window5_table` and `extended_mul_two_with_window5_tables`. Sub-2% standalone effect.
- Pre-size the window table and digit array with `Array::new(capacity=...)`.

### Refactor

- `decode_prime_order_point` now returns `ExtendedPoint` and shares a new `decode_small_order_check_point` helper with the verify path, removing redundant `extended_from_affine` calls. Public API unchanged.

### Chores

- `wb_hex_value` now `abort`s on invalid input, matching the other hex helpers.
- Document the rationale for the 1024-byte `sha512_update_chunk_size`.

## v0.2.1 - 2026-05-21

### Security

- Enforce prime-order subgroup membership for public keys during point decoding; reject small-order and cofactor-mixed points at verify time.
- Use a fixed-size lookup table for signing scalar selection, removing a data-dependent branch in the scalar multiplication step.

### Performance

- Stream SHA-512 input in bounded chunks instead of allocating a full concatenated `Array[UInt]` per call, reducing peak memory allocation during signing and verification.

### Tests

- Add whitebox tests for `extended_has_prime_order` covering valid and cofactor-mixed points.
- Add whitebox tests for `verify_report` (success, invalid, and error-string cases) in the `openssl-interop` tool.
- Add blackbox tests asserting that non-prime-order public keys are rejected.
- Extend the `openssl-interop` binary to expose `verify_result`, enabling cross-tool verification of error paths.

### Refactor

- Extract `verify_report` helper in `cmd/openssl-interop` to deduplicate result-formatting logic.

## v0.2.0 - 2026-05-15

### Breaking Changes

- All public functions (`sign`, `verify`, `verify_result`, `derive_public_key`, `SigningKey::from_seed`, `SigningKey::sign`, `SigningKey::public_key`, `VerifyingKey::from_public_key`, `VerifyingKey::public_key`, `VerifyingKey::verify`, `VerifyingKey::verify_result`) now accept `BytesView` for input and return `Bytes` instead of `Array[UInt]`.
- `SigningKey::sign` additionally drops its `Result` wrapper: the return type changes from `Result[Array[UInt], String]` to `Bytes`, because signing cannot fail once the `SigningKey` has been built.

### Security

- Reject non-canonical points, small-order points, and points outside the
  prime-order subgroup during point decoding.
- Return an error when the signature scalar `s` is non-canonical (`s >= L`).
- Verify the curve equation explicitly in `decode_point`.
- Use a fixed-iteration loop count in scalar multiplication, removing data-dependent branches in the windowed loop (affects both signing and verification). Note: this does not make scalar multiplication constant-time, because the underlying BigInt field arithmetic is still operand-dependent.
- Abort on overflow in `bigint_to_le_bytes` when the value exceeds the expected byte length, preventing silent byte truncation.

### Performance

- Replace the manual little-endian byte loop with `BigInt::from_octets`.
- Feed SHA-512 inputs in bounded chunks instead of materializing full
  concatenated `Array[UInt]` values for `prefix || message` and
  `R || A || message`.

### Tests

- Add blackbox tests for malformed Ed25519 inputs (bad public key, bad signature, flipped bits).
- Add tests for `s = L - 1` (largest canonical scalar) and multi-block SHA-512 messages.
- Add whitebox tests for `scalar_window5_digits` (zero input, boundary values, roundtrip on representative scalars).

### Tools

- Expand `tools/openssl-interop.nu` with six scenario groups: length matrix (14 message sizes), multi-iteration key generation, tamper rejection (message / R / S), public-key tamper rejection, reverse pubkey load, and external-seed injection from RFC 8032 test vector 1.
- Replace heuristic DER byte extraction with full-prefix-and-length-validated extraction for both the private seed and public key in the interop script.

### Docs

- Document strict verification behaviour and add benchmark baseline for v0.2.0.

### Chores

- Remove redundant `[:]` `Bytes`→`BytesView` conversions.
- Rename `Err` pattern bindings to avoid shadowing the `message` parameter.
- Remove redundant constructor annotations.
- Switch tests to use `@test.assert_eq` from `moonbitlang/core/test`.
