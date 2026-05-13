///|
fn hex_value(c : UInt16) -> UInt {
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
fn hex(input : String) -> Array[UInt] {
  if input.length() % 2 != 0 {
    abort("hex input must have even length")
  }
  let out : Array[UInt] = []
  for i = 0; i < input.length(); i = i + 2 {
    let hi = hex_value(input[i])
    let lo = hex_value(input[i + 1])
    out.push((hi << 4) | lo)
  }
  out
}

///|
fn assert_verifying_key_error(
  public_key : Array[UInt],
  expected : String,
) -> Unit raise {
  match @ed25519.VerifyingKey::from_public_key(public_key) {
    Err(message) => @test.assert_eq(message, expected)
    Ok(_) => abort("expected invalid public key to fail")
  }
}

///|
test "rfc8032 vector 1: empty message" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = hex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let signature = hex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  @test.assert_eq(@ed25519.derive_public_key(seed), Ok(public_key))
  @test.assert_eq(@ed25519.sign(seed, []), Ok(signature))
  let signing_key = @ed25519.SigningKey::from_seed(seed).unwrap()
  @test.assert_eq(signing_key.public_key(), public_key)
  @test.assert_eq(signing_key.sign([]), Ok(signature))
  assert_true(@ed25519.verify(public_key, [], signature))
}

///|
test "rfc8032 vector 2: one byte message" {
  let seed = hex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let public_key = hex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let message = hex("72")
  let signature = hex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  @test.assert_eq(@ed25519.derive_public_key(seed), Ok(public_key))
  @test.assert_eq(@ed25519.sign(seed, message), Ok(signature))
  assert_true(@ed25519.verify(public_key, message, signature))
}

///|
test "rfc8032 vector 3: two byte message" {
  let seed = hex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  )
  let public_key = hex(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  )
  let message = hex("af82")
  let signature = hex(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
  @test.assert_eq(@ed25519.derive_public_key(seed), Ok(public_key))
  @test.assert_eq(@ed25519.sign(seed, message), Ok(signature))
  assert_true(@ed25519.verify(public_key, message, signature))
}

///|
test "verification rejects tampered message and signature" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let message = hex("73656c662d6c6963656e7365")
  let signature = @ed25519.sign(seed, message).unwrap()
  let tampered_message = hex("73656c662d6c6963656e7364")
  assert_false(@ed25519.verify(public_key, tampered_message, signature))
  signature[0] = signature[0] ^ 1U
  assert_false(@ed25519.verify(public_key, message, signature))
}

///|
test "verification rejects non-canonical s scalar" {
  let seed = hex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let message = hex("72")
  let signature = @ed25519.sign(seed, message).unwrap()
  let non_canonical_s = hex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  for i = 0; i < 32; i = i + 1 {
    signature[32 + i] = non_canonical_s[i]
  }
  assert_false(@ed25519.verify(public_key, message, signature))
  @test.assert_eq(
    @ed25519.verify_result(public_key, message, signature),
    Err("signature S scalar is out of range"),
  )
}

///|
test "verification rejects small-order public keys" {
  let identity_public_key = hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let message = hex("616263")
  let forged_signature = hex(
    "5866666666666666666666666666666666666666666666666666666666666666" +
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_false(@ed25519.verify(identity_public_key, message, forged_signature))
  @test.assert_eq(
    @ed25519.verify_result(identity_public_key, message, forged_signature),
    Err("public key has small order"),
  )
  assert_verifying_key_error(identity_public_key, "public key has small order")
}

///|
test "verification rejects non-canonical identity encoding" {
  let non_canonical_identity = hex(
    "0100000000000000000000000000000000000000000000000000000000000080",
  )
  let forged_signature = hex(
    "5866666666666666666666666666666666666666666666666666666666666666" +
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_false(@ed25519.verify(non_canonical_identity, [0x61U], forged_signature))
  @test.assert_eq(
    @ed25519.verify_result(non_canonical_identity, [0x61U], forged_signature),
    Err("encoded point is not canonical"),
  )
  assert_verifying_key_error(non_canonical_identity, "encoded point is not canonical")
}

///|
test "verification rejects small-order signature r" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let signature_with_identity_r = hex(
    "0100000000000000000000000000000000000000000000000000000000000000" +
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_false(@ed25519.verify(public_key, [], signature_with_identity_r))
  @test.assert_eq(
    @ed25519.verify_result(public_key, [], signature_with_identity_r),
    Err("signature R has small order"),
  )
}

///|
test "openssl interop: verifies external Ed25519 signature" {
  let message = hex(
    "733866792d6c6963656e73653a7b22637573746f6d65724964223a2273656c66222c" +
    "22657870697265734174223a22323032372d30352d3035227d",
  )
  let public_key = hex(
    "74e90e5ff7e46c80ec509272bee032de8b3471e8544f144d0826f7a353aad576",
  )
  let signature = hex(
    "74f52c4d97e4c97eca42b27d242f8505791cafa00eb3f4a7ffea5f7520e92e36" +
    "b2ae98c9489542ed6cd33a5cd65c6cfb10af7310afb400ea392992c263cf2400",
  )
  assert_true(@ed25519.verify(public_key, message, signature))
  let verifying_key = @ed25519.VerifyingKey::from_public_key(public_key).unwrap()
  @test.assert_eq(verifying_key.public_key(), public_key)
  assert_true(verifying_key.verify(message, signature))
}

///|
test "malformed inputs return errors" {
  @test.assert_eq(@ed25519.derive_public_key([]), Err("seed must be 32 bytes"))
  match @ed25519.SigningKey::from_seed([]) {
    Err(message) => @test.assert_eq(message, "seed must be 32 bytes")
    Ok(_) => abort("expected invalid seed to fail")
  }
  match @ed25519.VerifyingKey::from_public_key([]) {
    Err(message) => @test.assert_eq(message, "public key must be 32 bytes")
    Ok(_) => abort("expected invalid public key to fail")
  }
  @test.assert_eq(@ed25519.sign([], []), Err("seed must be 32 bytes"))
  @test.assert_eq(
    @ed25519.sign(
      hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      [256U],
    ),
    Err("message: byte value must be in 0..255"),
  )
  @test.assert_eq(
    @ed25519.verify_result([], [], []),
    Err("public key must be 32 bytes"),
  )
}
