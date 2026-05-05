# hustcer/ed25519

A pure MoonBit Ed25519 package for deterministic signing and verification.

This implementation targets the S8FY license flow:

- sign compact viewer license payloads with a local 32-byte private seed
- verify 64-byte Ed25519 signatures from a 32-byte public key
- interoperate with RFC 8032 test vectors and standard Ed25519 tooling

## API

```moonbit nocheck
pub fn derive_public_key(seed : Array[UInt]) -> Result[Array[UInt], String]
pub fn sign(seed : Array[UInt], message : Array[UInt]) -> Result[Array[UInt], String]
pub fn verify(public_key : Array[UInt], message : Array[UInt], signature : Array[UInt]) -> Bool
pub fn verify_result(
  public_key : Array[UInt],
  message : Array[UInt],
  signature : Array[UInt]
) -> Result[Bool, String]
```

Inputs use `Array[UInt]` byte arrays. Every byte must be in `0..255`.

## Notes

The package is correctness-first and uses MoonBit `BigInt` arithmetic. That is enough for license signing and verification payloads, but it is not intended to be a constant-time general-purpose cryptography primitive yet.

Use a mature audited implementation for high-volume or side-channel-sensitive server cryptography. For S8FY, the recommended use is to sign license payloads offline and verify signatures inside the license policy layer.

## Benchmarks

Run:

```bash
moon bench --release
```

See `BENCHMARK.md` for the benchmark cases and workflow.
