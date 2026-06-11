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
fn hex(input : String) -> Bytes {
  if input.length() % 2 != 0 {
    abort("hex input must have even length")
  }
  Bytes::makei(input.length() / 2, fn(i) {
    let hi = hex_value(input[2 * i])
    let lo = hex_value(input[2 * i + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn with_byte_replaced(bytes : Bytes, index : Int, value : Byte) -> Bytes {
  Bytes::makei(bytes.length(), fn(i) {
    if i == index {
      value
    } else {
      bytes[i]
    }
  })
}

///|
fn assert_verifying_key_error(
  public_key : Bytes,
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
  let empty : Bytes = b""
  @test.assert_eq(@ed25519.derive_public_key(seed), Ok(public_key))
  @test.assert_eq(@ed25519.sign(seed, empty), Ok(signature))
  let signing_key = @ed25519.SigningKey::from_seed(seed).unwrap()
  @test.assert_eq(signing_key.public_key(), public_key)
  @test.assert_eq(signing_key.sign(empty), signature)
  assert_true(@ed25519.verify(public_key, empty, signature))
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
  let tampered_signature = with_byte_replaced(
    signature,
    0,
    signature[0] ^ b'\x01',
  )
  assert_false(@ed25519.verify(public_key, message, tampered_signature))
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
  let tampered = Bytes::makei(64, fn(i) {
    if i < 32 {
      signature[i]
    } else {
      non_canonical_s[i - 32]
    }
  })
  assert_false(@ed25519.verify(public_key, message, tampered))
  @test.assert_eq(
    @ed25519.verify_result(public_key, message, tampered),
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
test "verification rejects non-prime-order public keys" {
  // B plus a 4-torsion point: not small-order, but not in the prime-order subgroup.
  let torsion_mixed_public_key = hex(
    "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea",
  )
  let message = hex("616263")
  let forged_signature = hex(
    "5866666666666666666666666666666666666666666666666666666666666666" +
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_false(
    @ed25519.verify(torsion_mixed_public_key, message, forged_signature),
  )
  @test.assert_eq(
    @ed25519.verify_result(torsion_mixed_public_key, message, forged_signature),
    Err("public key is not in the prime-order subgroup"),
  )
  assert_verifying_key_error(
    torsion_mixed_public_key, "public key is not in the prime-order subgroup",
  )
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
  let single_byte_msg : Bytes = b"\x61"
  assert_false(
    @ed25519.verify(non_canonical_identity, single_byte_msg, forged_signature),
  )
  @test.assert_eq(
    @ed25519.verify_result(
      non_canonical_identity, single_byte_msg, forged_signature,
    ),
    Err("encoded point is not canonical"),
  )
  assert_verifying_key_error(
    non_canonical_identity, "encoded point is not canonical",
  )
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
  let empty : Bytes = b""
  assert_false(@ed25519.verify(public_key, empty, signature_with_identity_r))
  @test.assert_eq(
    @ed25519.verify_result(public_key, empty, signature_with_identity_r),
    Err("signature R has small order"),
  )
}

///|
test "verification rejects non-prime-order signature r" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let signature_with_torsion_mixed_r = hex(
    "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea" +
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let empty : Bytes = b""
  // s*B - k*A always lies in the prime-order subgroup, so the main
  // verification rejects a cofactor-mixed R before the defense-in-depth
  // prime-order check is reached. The R-subgroup error is therefore
  // mathematically unreachable here and the malformed-input report
  // collapses into Ok(false).
  assert_false(
    @ed25519.verify(public_key, empty, signature_with_torsion_mixed_r),
  )
  @test.assert_eq(
    @ed25519.verify_result(public_key, empty, signature_with_torsion_mixed_r),
    Ok(false),
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
test "SigningKey::verifying_key matches VerifyingKey::from_public_key" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let message : Bytes = b"license"
  let signing_key = @ed25519.SigningKey::from_seed(seed).unwrap()
  let verifying_key = signing_key.verifying_key()
  @test.assert_eq(verifying_key.public_key(), signing_key.public_key())
  let signature = signing_key.sign(message)
  assert_true(verifying_key.verify(message, signature))
  @test.assert_eq(verifying_key.verify_result(message, signature), Ok(true))
  // Rejects a different message and a tampered signature, like a key built
  // through the decoding path.
  assert_false(verifying_key.verify(b"licensf", signature))
  let tampered = with_byte_replaced(signature, 5, signature[5] ^ b'\x01')
  assert_false(verifying_key.verify(message, tampered))
  // Behaves identically to the key reconstructed from the encoded public key.
  let decoded_key = @ed25519.VerifyingKey::from_public_key(
    signing_key.public_key(),
  ).unwrap()
  @test.assert_eq(
    decoded_key.verify_result(message, signature),
    verifying_key.verify_result(message, signature),
  )
}

///|
test "malformed inputs return errors" {
  let empty : Bytes = b""
  @test.assert_eq(
    @ed25519.derive_public_key(empty),
    Err("seed must be 32 bytes"),
  )
  match @ed25519.SigningKey::from_seed(empty) {
    Err(message) => @test.assert_eq(message, "seed must be 32 bytes")
    Ok(_) => abort("expected invalid seed to fail")
  }
  match @ed25519.VerifyingKey::from_public_key(empty) {
    Err(message) => @test.assert_eq(message, "public key must be 32 bytes")
    Ok(_) => abort("expected invalid public key to fail")
  }
  @test.assert_eq(@ed25519.sign(empty, empty), Err("seed must be 32 bytes"))
  @test.assert_eq(
    @ed25519.verify_result(empty, empty, empty),
    Err("public key must be 32 bytes"),
  )
  // Non-empty but wrong-length public keys hit the same unified length check
  // in both the one-shot and the cached-key constructors.
  let short_key = Bytes::makei(31, fn(_) { b'\x01' })
  let long_key = Bytes::makei(33, fn(_) { b'\x01' })
  @test.assert_eq(
    @ed25519.verify_result(short_key, empty, empty),
    Err("public key must be 32 bytes"),
  )
  @test.assert_eq(
    @ed25519.verify_result(long_key, empty, empty),
    Err("public key must be 32 bytes"),
  )
  assert_verifying_key_error(short_key, "public key must be 32 bytes")
  assert_verifying_key_error(long_key, "public key must be 32 bytes")
}

///|
test "malformed point encodings return errors" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let empty : Bytes = b""
  let valid_signature = @ed25519.sign(seed, empty).unwrap()
  let y_equal_to_p = hex(
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  )
  @test.assert_eq(
    @ed25519.verify_result(y_equal_to_p, empty, valid_signature),
    Err("encoded point y coordinate is out of range"),
  )
  assert_verifying_key_error(
    y_equal_to_p, "encoded point y coordinate is out of range",
  )
  let signature_with_invalid_r = hex(
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" +
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  @test.assert_eq(
    @ed25519.verify_result(public_key, empty, signature_with_invalid_r),
    Err("encoded point y coordinate is out of range"),
  )
  // y = 2 is canonical but (y^2 - 1) / (1 + d*y^2) is a non-residue, so no x
  // satisfies the curve equation: exercises the square-root rejection branch.
  let y_not_on_curve = hex(
    "0200000000000000000000000000000000000000000000000000000000000000",
  )
  @test.assert_eq(
    @ed25519.verify_result(y_not_on_curve, empty, valid_signature),
    Err("encoded point is not on Ed25519"),
  )
  assert_verifying_key_error(y_not_on_curve, "encoded point is not on Ed25519")
}

///|
test "short signature is rejected" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let short : Bytes = b""
  @test.assert_eq(
    @ed25519.verify_result(public_key, short, short),
    Err("signature must be 64 bytes"),
  )
}

///|
test "verification distinguishes s = L from s < L" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let empty : Bytes = b""
  let valid_sig = @ed25519.sign(seed, empty).unwrap()
  // L - 1 in little-endian: largest scalar that should pass the s < L check.
  // The signature is still rejected at the curve check, but the error must
  // not be "out of range", which would imply the boundary is inclusive.
  let s_l_minus_1 = hex(
    "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let tampered = Bytes::makei(64, fn(i) {
    if i < 32 {
      valid_sig[i]
    } else {
      s_l_minus_1[i - 32]
    }
  })
  @test.assert_eq(
    @ed25519.verify_result(public_key, empty, tampered),
    Ok(false),
  )
}

///|
test "sign and verify message spanning multiple SHA-512 blocks" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  // SHA-512 block size is 128 bytes; 200 bytes guarantees a multi-block input.
  let long_message = Bytes::makei(200, fn(i) { (i % 256).to_byte() })
  let signature = @ed25519.sign(seed, long_message).unwrap()
  assert_true(@ed25519.verify(public_key, long_message, signature))
  let tampered_last_byte = Bytes::makei(200, fn(i) {
    if i == 199 {
      long_message[199] ^ b'\x01'
    } else {
      long_message[i]
    }
  })
  assert_false(@ed25519.verify(public_key, tampered_last_byte, signature))
}

///|
test "rfc8032 test 1024: 1023 byte message" {
  let seed = hex(
    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
  )
  let public_key = hex(
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
  )
  let message = hex(
    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
    "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
    "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
    "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
    "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
    "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
    "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
    "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
    "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
    "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
    "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
    "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
    "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
    "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
    "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
    "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
    "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
    "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
    "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
    "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
    "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
    "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
    "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
    "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
    "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
    "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
    "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
    "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
    "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
    "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
    "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
  )
  let signature = hex(
    "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
    "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
  )
  @test.assert_eq(@ed25519.derive_public_key(seed), Ok(public_key))
  @test.assert_eq(@ed25519.sign(seed, message), Ok(signature))
  assert_true(@ed25519.verify(public_key, message, signature))
}

///|
test "verification distinguishes s = 0 from s out of range" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let empty : Bytes = b""
  let valid_sig = @ed25519.sign(seed, empty).unwrap()
  // Replace S with zero while keeping the valid R. S = 0 is the smallest
  // canonical scalar (S < L); the boundary must not be reported as
  // out-of-range, even though the curve equation rejects the signature.
  let zero_s = Bytes::makei(64, fn(i) {
    if i < 32 {
      valid_sig[i]
    } else {
      b'\x00'
    }
  })
  @test.assert_eq(@ed25519.verify_result(public_key, empty, zero_s), Ok(false))
}

///|
test "verify wrapper collapses malformed-input errors to false" {
  let empty : Bytes = b""
  // public key must be 32 bytes
  assert_false(@ed25519.verify(empty, empty, empty))
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  // signature must be 64 bytes
  assert_false(@ed25519.verify(public_key, empty, empty))
  // small-order public key (verify_result returns Err, verify must yield false)
  let identity_public_key = hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let forged_signature = hex(
    "5866666666666666666666666666666666666666666666666666666666666666" +
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_false(@ed25519.verify(identity_public_key, empty, forged_signature))
}
