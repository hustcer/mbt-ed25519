///|
fn wb_hex_value(c : UInt16) -> UInt {
  if c >= 48 && c <= 57 {
    c.to_uint() - 48U
  } else if c >= 97 && c <= 102 {
    c.to_uint() - 97U + 10U
  } else {
    c.to_uint() - 65U + 10U
  }
}

///|
fn wb_hex(input : String) -> Bytes {
  Bytes::makei(input.length() / 2, fn(i) {
    let hi = wb_hex_value(input[2 * i])
    let lo = wb_hex_value(input[2 * i + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
test "sha512 byte order matches RFC8032 seed hash" {
  let seed = wb_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let expected = wb_hex(
    "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f" +
    "9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f",
  )
  @test.assert_eq(sha512(seed), expected)
}

///|
test "nonce scalar matches RFC8032 vector 1" {
  let seed = wb_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let digest = sha512(seed)
  let prefix = digest[32:64].to_owned()
  @test.assert_eq(
    prefix,
    wb_hex("9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f"),
  )
  @test.assert_eq(
    sha512(prefix),
    wb_hex(
      "b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4" +
      "044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d",
    ),
  )
  let r = modl(bytes_le_to_bigint(sha512(prefix)))
  let expected = wb_hex(
    "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404",
  )
  @test.assert_eq(bigint_to_le_bytes(r, 32), expected)
  @test.assert_eq(
    encode_extended_point(
      extended_mul_with_window5_table(r, extended_window5_table(base_point())),
    ),
    wb_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"),
  )
}

///|
test "windowed scalar multiplication handles identity and base point" {
  @test.assert_eq(
    encode_extended_point(
      extended_mul_with_window5_table(0N, extended_window5_table(base_point())),
    ),
    wb_hex("0100000000000000000000000000000000000000000000000000000000000000"),
  )
  @test.assert_eq(
    encode_extended_point(
      extended_mul_with_window5_table(1N, extended_window5_table(base_point())),
    ),
    wb_hex("5866666666666666666666666666666666666666666666666666666666666666"),
  )
}
