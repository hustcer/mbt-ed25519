///|
/// Errors raised by the fallible Ed25519 operations: seed expansion, public
/// key parsing, and strict signature verification. Match on the variants to
/// handle failure modes precisely; `Show` renders the same human-readable
/// messages the pre-0.5 `Result[_, String]` API returned.
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

///|
/// Keep the exact pre-0.5 message texts so logs and the OpenSSL interop
/// output remain stable; the structured payloads stay available to callers
/// through pattern matching and `Debug`.
pub impl Show for Ed25519Error with fn output(self, logger) {
  let message = match self {
    InvalidSeedLength(..) => "seed must be 32 bytes"
    InvalidPublicKeyLength(..) => "public key must be 32 bytes"
    InvalidSignatureLength(..) => "signature must be 64 bytes"
    PointYOutOfRange => "encoded point y coordinate is out of range"
    PointNotOnCurve => "encoded point is not on Ed25519"
    PointNotCanonical => "encoded point is not canonical"
    PublicKeySmallOrder => "public key has small order"
    SignatureRSmallOrder => "signature R has small order"
    PublicKeyNotPrimeOrder => "public key is not in the prime-order subgroup"
    SignatureSOutOfRange => "signature S scalar is out of range"
  }
  logger.write_string(message)
}
