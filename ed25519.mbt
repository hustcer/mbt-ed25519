///|
let p : BigInt = BigInt::from_string(
  "57896044618658097711785492504343953926634992332820282019728792003956564819949",
)

///|
let l : BigInt = BigInt::from_string(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989",
)

///|
let d : BigInt = BigInt::from_string(
  "37095705934669439343138083508754565189542113879843219016388785533085940283555",
)

///|
let sqrt_m1 : BigInt = BigInt::from_string(
  "19681161376707505956807079304988542015446066515923890162744021073123829784752",
)

///|
let bx : BigInt = BigInt::from_string(
  "15112221349535400772501151409588531511454012693041857206046113283949847762202",
)

///|
let by : BigInt = BigInt::from_string(
  "46316835694926478169428394003475163141307993866256225615783033603165251855960",
)

///|
priv struct Point {
  x : BigInt
  y : BigInt
}

///|
priv struct ExtendedPoint {
  x : BigInt
  y : BigInt
  z : BigInt
  t : BigInt
}

///|
/// Expanded Ed25519 signing key for repeated signing with the same seed.
pub struct SigningKey {
  priv a : BigInt
  priv prefix : Bytes
  priv public_key : Bytes
}

///|
/// Expanded Ed25519 verifying key for repeated verification.
pub struct VerifyingKey {
  priv public_key : Bytes
  priv neg_public_key_window5_table : Array[ExtendedPoint]
}

///|
fn base_point() -> ExtendedPoint {
  extended_from_affine({ x: bx, y: by })
}

///|
fn extended_identity() -> ExtendedPoint {
  { x: 0N, y: 1N, z: 1N, t: 0N }
}

///|
fn modp(x : BigInt) -> BigInt {
  let r = x % p
  if r < 0N {
    r + p
  } else {
    r
  }
}

///|
fn modl(x : BigInt) -> BigInt {
  let r = x % l
  if r < 0N {
    r + l
  } else {
    r
  }
}

///|
fn invp(x : BigInt) -> BigInt {
  modp(x).pow(p - 2N, modulus=p)
}

///|
fn field_eq(a : BigInt, b : BigInt) -> Bool {
  modp(a) == modp(b)
}

///|
fn extended_from_affine(point : Point) -> ExtendedPoint {
  { x: modp(point.x), y: modp(point.y), z: 1N, t: modp(point.x * point.y) }
}

///|
fn extended_to_affine(point : ExtendedPoint) -> Point {
  let iz = invp(point.z)
  { x: modp(point.x * iz), y: modp(point.y * iz) }
}

///|
fn extended_equal(a : ExtendedPoint, b : ExtendedPoint) -> Bool {
  field_eq(a.x * b.z, b.x * a.z) && field_eq(a.y * b.z, b.y * a.z)
}

///|
fn extended_has_small_order(point : ExtendedPoint) -> Bool {
  extended_equal(
    extended_double(extended_double(extended_double(point))),
    extended_identity(),
  )
}

///|
fn extended_neg(point : ExtendedPoint) -> ExtendedPoint {
  { x: modp(-point.x), y: point.y, z: point.z, t: modp(-point.t) }
}

///|
fn extended_add(a : ExtendedPoint, b : ExtendedPoint) -> ExtendedPoint {
  let a_term = modp((a.y - a.x) * (b.y - b.x))
  let b_term = modp((a.y + a.x) * (b.y + b.x))
  let c_term = modp(2N * d * a.t * b.t)
  let d_term = modp(2N * a.z * b.z)
  let e_term = modp(b_term - a_term)
  let f_term = modp(d_term - c_term)
  let g_term = modp(d_term + c_term)
  let h_term = modp(b_term + a_term)
  {
    x: modp(e_term * f_term),
    y: modp(g_term * h_term),
    z: modp(f_term * g_term),
    t: modp(e_term * h_term),
  }
}

///|
fn extended_double(point : ExtendedPoint) -> ExtendedPoint {
  let a_term = modp(point.x * point.x)
  let b_term = modp(point.y * point.y)
  let c_term = modp(2N * point.z * point.z)
  let d_term = modp(-a_term)
  let e_term = modp((point.x + point.y) * (point.x + point.y) - a_term - b_term)
  let g_term = modp(d_term + b_term)
  let f_term = modp(g_term - c_term)
  let h_term = modp(d_term - b_term)
  {
    x: modp(e_term * f_term),
    y: modp(g_term * h_term),
    z: modp(f_term * g_term),
    t: modp(e_term * h_term),
  }
}

///|
fn extended_window5_table(point : ExtendedPoint) -> Array[ExtendedPoint] {
  let table : Array[ExtendedPoint] = []
  table.push(extended_identity())
  for i in 1..<32 {
    table.push(extended_add(table[i - 1], point))
  }
  table
}

///|
fn scalar_window5_digits(s : BigInt) -> Array[Int] {
  let digits : Array[Int] = []
  let mut n = s
  for _ in 0..<51 {
    digits.push((n % 32N).to_int())
    n = n / 32N
  }
  digits
}

///|
fn extended_mul_with_window5_table(
  s : BigInt,
  table : Array[ExtendedPoint],
) -> ExtendedPoint {
  let digits = scalar_window5_digits(s)
  let mut acc = extended_identity()
  for i = digits.length() - 1; i >= 0; i = i - 1 {
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    let digit = digits[i]
    acc = extended_add(acc, table[digit])
  }
  acc
}

///|
fn extended_mul_two_with_window5_tables(
  a_scalar : BigInt,
  a_table : Array[ExtendedPoint],
  b_scalar : BigInt,
  b_table : Array[ExtendedPoint],
) -> ExtendedPoint {
  let a_digits = scalar_window5_digits(a_scalar)
  let b_digits = scalar_window5_digits(b_scalar)
  let mut acc = extended_identity()
  for i = a_digits.length() - 1; i >= 0; i = i - 1 {
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_add(acc, a_table[a_digits[i]])
    acc = extended_add(acc, b_table[b_digits[i]])
  }
  acc
}

///|
let base_point_window5_table : Array[ExtendedPoint] = extended_window5_table(
  base_point(),
)

///|
fn base_point_mul(s : BigInt) -> ExtendedPoint {
  extended_mul_with_window5_table(s, base_point_window5_table)
}

///|
fn bytes_le_to_bigint(bytes : BytesView) -> BigInt {
  let length = bytes.length()
  if length == 0 {
    return 0N
  }
  let be = Bytes::makei(length, fn(i) { bytes[length - 1 - i] })
  BigInt::from_octets(be)
}

///|
fn bigint_to_le_bytes(value : BigInt, length : Int) -> Bytes {
  let be = value.to_octets(length~)
  // BigInt::to_octets returns >= length bytes; reject the overflow case so the
  // caller does not silently get the high-order bytes when value >= 2^(8*length).
  if be.length() != length {
    abort("bigint_to_le_bytes: value exceeds \{length} bytes")
  }
  Bytes::makei(length, fn(i) { be[length - 1 - i] })
}

///|
fn sha512_words_to_bytes(words : FixedArray[UInt64]) -> Bytes {
  Bytes::makei(64, fn(i) {
    let word_idx = i / 8
    let byte_in_word = 7 - i % 8
    ((words[word_idx] >> (byte_in_word * 8)) & 0xffUL).to_byte()
  })
}

///|
fn bytes_view_to_uint_array(bytes : BytesView) -> Array[UInt] {
  let arr : Array[UInt] = Array::new(capacity=bytes.length())
  for byte in bytes {
    arr.push(byte.to_uint())
  }
  arr
}

///|
fn sha512(input : BytesView) -> Bytes {
  sha512_words_to_bytes(@sha2.Sha512::digest(bytes_view_to_uint_array(input)))
}

///|
fn sha512_concat2(a : BytesView, b : BytesView) -> Bytes {
  let sha = @sha2.Sha512::new()
  sha.update(bytes_view_to_uint_array(a))
  sha.update(bytes_view_to_uint_array(b))
  sha512_words_to_bytes(sha.finalize())
}

///|
fn sha512_concat3(a : BytesView, b : BytesView, c : BytesView) -> Bytes {
  let sha = @sha2.Sha512::new()
  sha.update(bytes_view_to_uint_array(a))
  sha.update(bytes_view_to_uint_array(b))
  sha.update(bytes_view_to_uint_array(c))
  sha512_words_to_bytes(sha.finalize())
}

///|
fn clamp_scalar(bytes : BytesView) -> Bytes {
  Bytes::makei(32, fn(i) {
    match i {
      0 => bytes[0] & b'\xf8'
      31 => (bytes[31] & b'\x3f') | b'\x40'
      _ => bytes[i]
    }
  })
}

///|
fn encode_point(point : Point) -> Bytes {
  let y_bytes = bigint_to_le_bytes(modp(point.y), 32)
  if modp(point.x) % 2N == 1N {
    Bytes::makei(32, fn(i) {
      if i == 31 {
        y_bytes[31] | b'\x80'
      } else {
        y_bytes[i]
      }
    })
  } else {
    y_bytes
  }
}

///|
fn encode_extended_point(point : ExtendedPoint) -> Bytes {
  encode_point(extended_to_affine(point))
}

///|
fn decode_point(bytes : BytesView) -> Result[Point, String] {
  if bytes.length() != 32 {
    return Err("encoded point must be 32 bytes")
  }
  let sign : Byte = (bytes[31] >> 7) & b'\x01'
  let y_bytes = Bytes::makei(32, fn(i) {
    if i == 31 {
      bytes[31] & b'\x7f'
    } else {
      bytes[i]
    }
  })
  let y = bytes_le_to_bigint(y_bytes)
  if y >= p {
    return Err("encoded point y coordinate is out of range")
  }
  let y2 = modp(y * y)
  let u = modp(y2 - 1N)
  let v = modp(d * y2 + 1N)
  let xx = modp(u * invp(v))
  let mut x = xx.pow((p + 3N) / 8N, modulus=p)
  if !field_eq(x * x, xx) {
    x = modp(x * sqrt_m1)
  }
  // Verify the curve equation -x^2 + y^2 == 1 + d*x^2*y^2 directly so the
  // result does not silently rely on `invp(0)` returning 0 when v == 0.
  let x2 = modp(x * x)
  if !field_eq(modp(y2 - x2), modp(1N + d * x2 * y2)) {
    return Err("encoded point is not on Ed25519")
  }
  if (x % 2N == 1N) != (sign == b'\x01') {
    x = modp(p - x)
  }
  let point = { x, y }
  if encode_point(point)[:] != bytes {
    return Err("encoded point is not canonical")
  }
  Ok(point)
}

///|
fn decode_prime_order_point(
  bytes : BytesView,
  name : String,
) -> Result[Point, String] {
  let point = match decode_point(bytes) {
    Err(err) => return Err(err)
    Ok(point) => point
  }
  if extended_has_small_order(extended_from_affine(point)) {
    return Err("\{name} has small order")
  }
  Ok(point)
}

///|
fn expanded_secret(seed : BytesView) -> Result[(BigInt, Bytes), String] {
  if seed.length() != 32 {
    return Err("seed must be 32 bytes")
  }
  let digest = sha512(seed)
  let a_bytes = clamp_scalar(digest[0:32])
  let prefix = digest[32:64].to_owned()
  Ok((bytes_le_to_bigint(a_bytes), prefix))
}

///|
fn sign_with_expanded_key(
  a : BigInt,
  prefix : BytesView,
  public_key : BytesView,
  message : BytesView,
) -> Bytes {
  let r = modl(bytes_le_to_bigint(sha512_concat2(prefix, message)))
  let r_encoded = encode_extended_point(base_point_mul(r))
  let k = modl(
    bytes_le_to_bigint(sha512_concat3(r_encoded, public_key, message)),
  )
  let s = modl(r + k * a)
  r_encoded + bigint_to_le_bytes(s, 32)
}

///|
/// Create an expanded signing key from a 32-byte Ed25519 private seed.
pub fn SigningKey::from_seed(seed : BytesView) -> Result[SigningKey, String] {
  match expanded_secret(seed) {
    Err(err) => Err(err)
    Ok((a, prefix)) => {
      let public_key = encode_extended_point(base_point_mul(a))
      Ok({ a, prefix, public_key })
    }
  }
}

///|
/// Return the 32-byte public key for this signing key.
pub fn SigningKey::public_key(self : SigningKey) -> Bytes {
  self.public_key
}

///|
/// Sign a message with a pre-expanded Ed25519 signing key.
pub fn SigningKey::sign(self : SigningKey, message : BytesView) -> Bytes {
  sign_with_expanded_key(self.a, self.prefix, self.public_key, message)
}

///|
/// Create an expanded verifying key from a 32-byte Ed25519 public key.
pub fn VerifyingKey::from_public_key(
  public_key : BytesView,
) -> Result[VerifyingKey, String] {
  if public_key.length() != 32 {
    return Err("public key must be 32 bytes")
  }
  let point = match decode_prime_order_point(public_key, "public key") {
    Err(err) => return Err(err)
    Ok(point) => point
  }
  Ok({
    public_key: public_key.to_owned(),
    neg_public_key_window5_table: extended_window5_table(
      extended_neg(extended_from_affine(point)),
    ),
  })
}

///|
/// Return the 32-byte public key for this verifying key.
pub fn VerifyingKey::public_key(self : VerifyingKey) -> Bytes {
  self.public_key
}

///|
/// Verify a signature with a pre-expanded verifying key.
pub fn VerifyingKey::verify(
  self : VerifyingKey,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  self.verify_result(message, signature).unwrap_or(false)
}

///|
/// Verify a signature with a pre-expanded verifying key and report malformed inputs.
pub fn VerifyingKey::verify_result(
  self : VerifyingKey,
  message : BytesView,
  signature : BytesView,
) -> Result[Bool, String] {
  verify_with_neg_public_key_table(
    self.public_key,
    self.neg_public_key_window5_table,
    message,
    signature,
  )
}

///|
/// Derive a 32-byte Ed25519 public key from a 32-byte private seed.
pub fn derive_public_key(seed : BytesView) -> Result[Bytes, String] {
  match expanded_secret(seed) {
    Err(err) => Err(err)
    Ok((a, _prefix)) => Ok(encode_extended_point(base_point_mul(a)))
  }
}

///|
/// Sign a message with a 32-byte Ed25519 private seed.
pub fn sign(seed : BytesView, message : BytesView) -> Result[Bytes, String] {
  match expanded_secret(seed) {
    Err(err) => Err(err)
    Ok((a, prefix)) => {
      let public_key = encode_extended_point(base_point_mul(a))
      Ok(sign_with_expanded_key(a, prefix, public_key, message))
    }
  }
}

///|
/// Verify a 64-byte Ed25519 signature for a message and 32-byte public key.
pub fn verify(
  public_key : BytesView,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  verify_result(public_key, message, signature).unwrap_or(false)
}

///|
/// Verify a signature and return an error for malformed public inputs.
pub fn verify_result(
  public_key : BytesView,
  message : BytesView,
  signature : BytesView,
) -> Result[Bool, String] {
  if public_key.length() != 32 {
    return Err("public key must be 32 bytes")
  }
  let a = match decode_prime_order_point(public_key, "public key") {
    Err(err) => return Err(err)
    Ok(point) => point
  }
  verify_with_neg_public_key_table(
    public_key,
    extended_window5_table(extended_neg(extended_from_affine(a))),
    message,
    signature,
  )
}

///|
fn verify_with_neg_public_key_table(
  public_key : BytesView,
  neg_public_key_window5_table : Array[ExtendedPoint],
  message : BytesView,
  signature : BytesView,
) -> Result[Bool, String] {
  if signature.length() != 64 {
    return Err("signature must be 64 bytes")
  }
  let r_encoded = signature[0:32]
  let s_bytes = signature[32:64]
  let s = bytes_le_to_bigint(s_bytes)
  if s >= l {
    return Err("signature S scalar is out of range")
  }
  let r = match decode_point(r_encoded) {
    Err(err) => return Err(err)
    Ok(point) => point
  }
  if extended_has_small_order(extended_from_affine(r)) {
    return Err("signature R has small order")
  }
  let k = modl(
    bytes_le_to_bigint(sha512_concat3(r_encoded, public_key, message)),
  )
  let combined = extended_mul_two_with_window5_tables(
    s, base_point_window5_table, k, neg_public_key_window5_table,
  )
  Ok(extended_equal(combined, extended_from_affine(r)))
}
