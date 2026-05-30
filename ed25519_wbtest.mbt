///|
fn wb_hex_value(c : UInt16) -> UInt {
  if c >= 48 && c <= 57 {
    c.to_uint() - 48U
  } else if c >= 97 && c <= 102 {
    c.to_uint() - 97U + 10U
  } else if c >= 65 && c <= 70 {
    c.to_uint() - 65U + 10U
  } else {
    abort("invalid hex")
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
fn direct_sha512_concat3(a : BytesView, b : BytesView, c : BytesView) -> Bytes {
  let arr : Array[UInt] = Array::new(
    capacity=a.length() + b.length() + c.length(),
  )
  wb_append_bytes_as_uint(arr, a)
  wb_append_bytes_as_uint(arr, b)
  wb_append_bytes_as_uint(arr, c)
  sha512_words_to_bytes(@sha2.Sha512::digest(arr))
}

///|
fn wb_append_bytes_as_uint(arr : Array[UInt], bytes : BytesView) -> Unit {
  for byte in bytes {
    arr.push(byte.to_uint())
  }
}

///|
test "sha512 streaming helpers match direct digest across chunk boundaries" {
  let a = Bytes::makei(17, fn(i) { (i + 1).to_byte() })
  let b = Bytes::makei(sha512_update_chunk_size + 19, fn(i) {
    ((i * 3 + 7) % 256).to_byte()
  })
  let c = Bytes::makei(sha512_update_chunk_size * 2 + 5, fn(i) {
    ((i * 5 + 11) % 256).to_byte()
  })
  @test.assert_eq(sha512(a), direct_sha512_concat3(a, b"", b""))
  @test.assert_eq(sha512_concat2(a, b), direct_sha512_concat3(a, b, b""))
  @test.assert_eq(sha512_concat3(a, b, c), direct_sha512_concat3(a, b, c))
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

///|
test "prime-order check accepts base point and RFC8032 public key" {
  assert_true(extended_has_prime_order(base_point()))
  let rfc_public_key = wb_hex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let point = decode_point(rfc_public_key).unwrap()
  assert_true(extended_has_prime_order(extended_from_affine(point)))
}

///|
test "prime-order check rejects torsion coset without small order" {
  let torsion_mixed = wb_hex(
    "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea",
  )
  let extended = extended_from_affine(decode_point(torsion_mixed).unwrap())
  assert_false(extended_has_small_order(extended))
  assert_false(extended_has_prime_order(extended))
}

///|
test "windowed scalar selection scans all digit slots" {
  let table = extended_window5_table(base_point())
  for digit in 0..<32 {
    @test.assert_eq(
      encode_extended_point(extended_select_window5(table, digit)),
      encode_extended_point(table[digit]),
    )
  }
}

///|
fn reassemble_window5(digits : Array[Int]) -> BigInt {
  let mut acc = 0N
  let mut factor = 1N
  for d in digits {
    acc = acc + BigInt::from_int(d) * factor
    factor = factor * 32N
  }
  acc
}

///|
test "scalar_window5_digits zero produces 51 zero digits" {
  let digits = scalar_window5_digits(0N)
  @test.assert_eq(digits.length(), 51)
  for d in digits {
    @test.assert_eq(d, 0)
  }
}

///|
test "scalar_window5_digits boundary digits" {
  // Lowest digit is 1.
  @test.assert_eq(scalar_window5_digits(1N)[0], 1)
  // 31 = 0b11111 fits in one digit.
  @test.assert_eq(scalar_window5_digits(31N)[0], 31)
  // 32 = 0b100000 spills into the next window.
  let d32 = scalar_window5_digits(32N)
  @test.assert_eq(d32[0], 0)
  @test.assert_eq(d32[1], 1)
  // 0x3e0 = 0b11111_00000: window 0 is 0, window 1 is the full 5-bit max 31.
  let straddle = scalar_window5_digits(BigInt::from_int(0x3e0))
  @test.assert_eq(straddle[0], 0)
  @test.assert_eq(straddle[1], 0x1f)
  @test.assert_eq(straddle[2], 0)
  // 1 << 250 places a 1 in the top window (slot 50, bits 250..254) and
  // exercises the last iteration of the 51-window loop.
  let top = scalar_window5_digits(BigInt::from_int(1) << 250)
  @test.assert_eq(top.length(), 51)
  @test.assert_eq(top[50], 1)
  for i in 0..<50 {
    @test.assert_eq(top[i], 0)
  }
}

///|
test "scalar_window5_digits roundtrip on representative scalars" {
  let cases = [
    0N,
    1N,
    BigInt::from_string("123456789012345678901234567890"),
    BigInt::from_string(
      "7237005577332262213973186563042994240857116359379907606001950938285454250988",
    ),
    BigInt::from_string(
      "57896044618658097711785492504343953926418782139537452191302581570759080747168",
    ),
  ]
  for s in cases {
    @test.assert_eq(reassemble_window5(scalar_window5_digits(s)), s)
  }
}

///|
test "lazy reduction: extended_double equals extended_add with same point" {
  let bp = base_point()
  let doubled = extended_double(bp)
  let added = extended_add(bp, bp)
  @test.assert_eq(encode_extended_point(doubled), encode_extended_point(added))
}

///|
test "lazy reduction: double-add chain consistency" {
  // Verify 2*P == P+P for multiple successive doubles along the curve,
  // exercising lazy reduction with progressively different coordinate values
  // that include negative intermediate terms.
  let bp = base_point()
  let mut point = bp
  for _ in 0..<5 {
    let doubled = extended_double(point)
    let added = extended_add(point, point)
    @test.assert_eq(
      encode_extended_point(doubled),
      encode_extended_point(added),
    )
    point = doubled
  }
}

///|
test "lazy reduction: add commutativity and associativity" {
  let bp = base_point()
  let p2 = extended_double(bp)
  // Commutativity: B + 2B == 2B + B
  @test.assert_eq(
    encode_extended_point(extended_add(bp, p2)),
    encode_extended_point(extended_add(p2, bp)),
  )
  // Associativity: (B + B) + B == B + (B + B)
  let lhs = extended_add(extended_add(bp, bp), bp)
  let rhs = extended_add(bp, extended_add(bp, bp))
  @test.assert_eq(encode_extended_point(lhs), encode_extended_point(rhs))
}

///|
test "lazy reduction: encode-decode roundtrip after repeated operations" {
  // Build 5*B via add chain, encode, decode, re-encode and compare.
  // This catches any reduction error that would produce a non-canonical or
  // wrong point encoding.
  let bp = base_point()
  let p5 = extended_add(extended_double(extended_double(bp)), bp)
  let encoded = encode_extended_point(p5)
  let decoded = decode_point(encoded).unwrap()
  let re_extended = extended_from_affine(decoded)
  @test.assert_eq(encode_extended_point(re_extended), encoded)
}

///|
test "sha512 buffer reuse: exact chunk-size multiple and single byte" {
  // Exact multiple of chunk size — every chunk is full, clear() path exercised
  let exact = Bytes::makei(sha512_update_chunk_size * 2, fn(i) {
    ((i * 7 + 13) % 256).to_byte()
  })
  @test.assert_eq(sha512(exact), direct_sha512_concat3(exact, b"", b""))
  // Single byte — shorter than one chunk, buffer reused after a single clear
  let single : Bytes = b"\x42"
  @test.assert_eq(sha512(single), direct_sha512_concat3(single, b"", b""))
}

///|
test "sha512 buffer reuse: concat with mixed chunk-aligned sizes" {
  // One input exactly one chunk, another straddling a chunk boundary —
  // verifies buffer is correctly cleared between sha512_update_bytes calls.
  let aligned = Bytes::makei(sha512_update_chunk_size, fn(i) {
    ((i + 3) % 256).to_byte()
  })
  let straddling = Bytes::makei(sha512_update_chunk_size + 1, fn(i) {
    ((i * 11 + 5) % 256).to_byte()
  })
  @test.assert_eq(
    sha512_concat2(aligned, straddling),
    direct_sha512_concat3(aligned, straddling, b""),
  )
}
