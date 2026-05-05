///|
fn bench_hex_value(c : UInt16) -> UInt {
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
fn bench_hex(input : String) -> Array[UInt] {
  if input.length() % 2 != 0 {
    abort("hex input must have even length")
  }
  let out : Array[UInt] = []
  for i = 0; i < input.length(); i = i + 2 {
    out.push((bench_hex_value(input[i]) << 4) | bench_hex_value(input[i + 1]))
  }
  out
}

///|
fn bench_seed() -> Array[UInt] {
  bench_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
}

///|
fn bench_license_payload() -> Array[UInt] {
  bench_hex(
    "7b22637573746f6d65724964223a2273656c66222c22657870697265734174223a" +
    "22323032372d30352d3035222c2270726f64756374223a22733866792d766965" +
    "776572227d",
  )
}

///|
test "bench: derive public key from seed" (b : @bench.T) {
  let seed = bench_seed()
  b.bench(fn() { b.keep(@ed25519.derive_public_key(seed).unwrap()) })
}

///|
test "bench: sign license-sized payload" (b : @bench.T) {
  let seed = bench_seed()
  let message = bench_license_payload()
  b.bench(fn() { b.keep(@ed25519.sign(seed, message).unwrap()) })
}

///|
test "bench: sign license-sized payload with cached SigningKey" (b : @bench.T) {
  let signing_key = @ed25519.SigningKey::from_seed(bench_seed()).unwrap()
  let message = bench_license_payload()
  b.bench(fn() { b.keep(signing_key.sign(message).unwrap()) })
}

///|
test "bench: verify license-sized payload" (b : @bench.T) {
  let seed = bench_seed()
  let message = bench_license_payload()
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let signature = @ed25519.sign(seed, message).unwrap()
  b.bench(fn() { b.keep(@ed25519.verify(public_key, message, signature)) })
}

///|
test "bench: verify license-sized payload with cached VerifyingKey" (
  b : @bench.T,
) {
  let seed = bench_seed()
  let message = bench_license_payload()
  let public_key = @ed25519.derive_public_key(seed).unwrap()
  let verifying_key = @ed25519.VerifyingKey::from_public_key(public_key).unwrap()
  let signature = @ed25519.sign(seed, message).unwrap()
  b.bench(fn() { b.keep(verifying_key.verify(message, signature)) })
}

///|
test "bench: verify OpenSSL Ed25519 signature" (b : @bench.T) {
  let message = bench_hex(
    "733866792d6c6963656e73653a7b22637573746f6d65724964223a2273656c66222c" +
    "22657870697265734174223a22323032372d30352d3035227d",
  )
  let public_key = bench_hex(
    "74e90e5ff7e46c80ec509272bee032de8b3471e8544f144d0826f7a353aad576",
  )
  let signature = bench_hex(
    "74f52c4d97e4c97eca42b27d242f8505791cafa00eb3f4a7ffea5f7520e92e36" +
    "b2ae98c9489542ed6cd33a5cd65c6cfb10af7310afb400ea392992c263cf2400",
  )
  b.bench(fn() { b.keep(@ed25519.verify(public_key, message, signature)) })
}

///|
test "bench: verify OpenSSL Ed25519 signature with cached VerifyingKey" (
  b : @bench.T,
) {
  let message = bench_hex(
    "733866792d6c6963656e73653a7b22637573746f6d65724964223a2273656c66222c" +
    "22657870697265734174223a22323032372d30352d3035227d",
  )
  let public_key = bench_hex(
    "74e90e5ff7e46c80ec509272bee032de8b3471e8544f144d0826f7a353aad576",
  )
  let verifying_key = @ed25519.VerifyingKey::from_public_key(public_key).unwrap()
  let signature = bench_hex(
    "74f52c4d97e4c97eca42b27d242f8505791cafa00eb3f4a7ffea5f7520e92e36" +
    "b2ae98c9489542ed6cd33a5cd65c6cfb10af7310afb400ea392992c263cf2400",
  )
  b.bench(fn() { b.keep(verifying_key.verify(message, signature)) })
}
