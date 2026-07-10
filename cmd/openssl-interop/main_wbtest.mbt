///|
test "verify_report formats successful verification" {
  @test.assert_eq(verify_report(() => true), (true, "ok"))
}

///|
test "verify_report formats invalid signature" {
  @test.assert_eq(verify_report(() => false), (false, "invalid"))
}

///|
test "verify_report preserves malformed input error" {
  @test.assert_eq(
    verify_report(() => raise PublicKeyNotPrimeOrder),
    (false, "public key is not in the prime-order subgroup"),
  )
}

///|
test "hex helpers accept mixed case and roundtrip bytes" {
  let bytes = hex_to_bytes("00aF10ff")
  @test.assert_eq(bytes, b"\x00\xaf\x10\xff")
  @test.assert_eq(bytes_to_hex(bytes), "00af10ff")
  @test.assert_eq(bytes_to_hex(b""), "")
}

///|
test "panic hex_to_bytes rejects odd-length input" {
  ignore(hex_to_bytes("0"))
}

///|
test "panic hex_to_bytes rejects non-hex input" {
  ignore(hex_to_bytes("0g"))
}
