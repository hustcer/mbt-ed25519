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
fn extended_window4_table(point : ExtendedPoint) -> Array[ExtendedPoint] {
  let table : Array[ExtendedPoint] = []
  table.push(extended_identity())
  for i in 1..<16 {
    table.push(extended_add(table[i - 1], point))
  }
  table
}

///|
fn scalar_window4_digits(s : BigInt) -> Array[Int] {
  let digits : Array[Int] = []
  let mut n = s
  while n > 0N {
    digits.push((n % 16N).to_int())
    n = n / 16N
  }
  digits
}

///|
fn extended_mul_with_window4_table(
  s : BigInt,
  table : Array[ExtendedPoint],
) -> ExtendedPoint {
  let digits = scalar_window4_digits(s)
  if digits.length() == 0 {
    return extended_identity()
  }
  let mut acc = extended_identity()
  for i = digits.length() - 1; i >= 0; i = i - 1 {
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    acc = extended_double(acc)
    let digit = digits[i]
    if digit != 0 {
      acc = extended_add(acc, table[digit])
    }
  }
  acc
}

///|
fn extended_mul(s : BigInt, point : ExtendedPoint) -> ExtendedPoint {
  extended_mul_with_window4_table(s, extended_window4_table(point))
}

///|
let base_point_window4_table : Array[ExtendedPoint] = extended_window4_table(
  base_point(),
)

///|
fn base_point_mul(s : BigInt) -> ExtendedPoint {
  extended_mul_with_window4_table(s, base_point_window4_table)
}

///|
fn byte_checked(value : UInt) -> Result[UInt, String] {
  if value <= 255U {
    Ok(value)
  } else {
    Err("byte value must be in 0..255")
  }
}

///|
fn validate_bytes(
  bytes : Array[UInt],
  expected_len : Int,
  name : String,
) -> Result[Unit, String] {
  if bytes.length() != expected_len {
    return Err("\{name} must be \{expected_len} bytes")
  }
  validate_byte_values(bytes, name)
}

///|
fn validate_byte_values(
  bytes : Array[UInt],
  name : String,
) -> Result[Unit, String] {
  for byte in bytes {
    match byte_checked(byte) {
      Ok(_) => ()
      Err(message) => return Err("\{name}: \{message}")
    }
  }
  Ok(())
}

///|
fn concat2(a : Array[UInt], b : Array[UInt]) -> Array[UInt] {
  let out : Array[UInt] = []
  for byte in a {
    out.push(byte)
  }
  for byte in b {
    out.push(byte)
  }
  out
}

///|
fn concat3(a : Array[UInt], b : Array[UInt], c : Array[UInt]) -> Array[UInt] {
  concat2(concat2(a, b), c)
}

///|
fn slice_bytes(bytes : Array[UInt], start : Int, end : Int) -> Array[UInt] {
  let out : Array[UInt] = []
  for i = start; i < end; i = i + 1 {
    out.push(bytes[i])
  }
  out
}

///|
fn bytes_le_to_bigint(bytes : Array[UInt]) -> BigInt {
  let mut out = 0N
  let mut factor = 1N
  for byte in bytes {
    out = out + BigInt::from_uint(byte) * factor
    factor = factor * 256N
  }
  out
}

///|
fn bigint_to_le_bytes(value : BigInt, length : Int) -> Array[UInt] {
  let be = value.to_octets(length~)
  let out : Array[UInt] = []
  for i = 0; i < length; i = i + 1 {
    out.push(be[length - 1 - i].to_uint())
  }
  out
}

///|
fn sha512(input : Array[UInt]) -> Array[UInt] {
  let words = @sha2.Sha512::digest(input)
  let out : Array[UInt] = []
  for word in words {
    out.push(((word >> 56) & 0xffUL).to_uint())
    out.push(((word >> 48) & 0xffUL).to_uint())
    out.push(((word >> 40) & 0xffUL).to_uint())
    out.push(((word >> 32) & 0xffUL).to_uint())
    out.push(((word >> 24) & 0xffUL).to_uint())
    out.push(((word >> 16) & 0xffUL).to_uint())
    out.push(((word >> 8) & 0xffUL).to_uint())
    out.push((word & 0xffUL).to_uint())
  }
  out
}

///|
fn clamp_scalar(bytes : Array[UInt]) -> Array[UInt] {
  let out : Array[UInt] = []
  for byte in bytes {
    out.push(byte)
  }
  out[0] = out[0] & 248U
  out[31] = (out[31] & 63U) | 64U
  out
}

///|
fn encode_point(point : Point) -> Array[UInt] {
  let out = bigint_to_le_bytes(modp(point.y), 32)
  if modp(point.x) % 2N == 1N {
    out[31] = out[31] | 128U
  }
  out
}

///|
fn encode_extended_point(point : ExtendedPoint) -> Array[UInt] {
  encode_point(extended_to_affine(point))
}

///|
fn decode_point(bytes : Array[UInt]) -> Result[Point, String] {
  match validate_bytes(bytes, 32, "encoded point") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let y_bytes : Array[UInt] = []
  for byte in bytes {
    y_bytes.push(byte)
  }
  let sign = (y_bytes[31] >> 7) & 1U
  y_bytes[31] = y_bytes[31] & 127U
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
  if !field_eq(x * x, xx) {
    return Err("encoded point is not on Ed25519")
  }
  if (x % 2N == 1N) != (sign == 1U) {
    x = modp(p - x)
  }
  Ok({ x, y })
}

///|
fn expanded_secret(seed : Array[UInt]) -> Result[(BigInt, Array[UInt]), String] {
  match validate_bytes(seed, 32, "seed") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let digest = sha512(seed)
  let a_bytes = clamp_scalar(slice_bytes(digest, 0, 32))
  let prefix = slice_bytes(digest, 32, 64)
  Ok((bytes_le_to_bigint(a_bytes), prefix))
}

///|
/// Derive a 32-byte Ed25519 public key from a 32-byte private seed.
pub fn derive_public_key(seed : Array[UInt]) -> Result[Array[UInt], String] {
  match expanded_secret(seed) {
    Err(message) => Err(message)
    Ok((a, _prefix)) => Ok(encode_extended_point(base_point_mul(a)))
  }
}

///|
/// Sign a message with a 32-byte Ed25519 private seed.
pub fn sign(
  seed : Array[UInt],
  message : Array[UInt],
) -> Result[Array[UInt], String] {
  match validate_byte_values(message, "message") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  match expanded_secret(seed) {
    Err(message) => Err(message)
    Ok((a, prefix)) => {
      let public_key = encode_extended_point(base_point_mul(a))
      let r = modl(bytes_le_to_bigint(sha512(concat2(prefix, message))))
      let r_encoded = encode_extended_point(base_point_mul(r))
      let k = modl(
        bytes_le_to_bigint(sha512(concat3(r_encoded, public_key, message))),
      )
      let s = modl(r + k * a)
      Ok(concat2(r_encoded, bigint_to_le_bytes(s, 32)))
    }
  }
}

///|
/// Verify a 64-byte Ed25519 signature for a message and 32-byte public key.
pub fn verify(
  public_key : Array[UInt],
  message : Array[UInt],
  signature : Array[UInt],
) -> Bool {
  verify_result(public_key, message, signature).unwrap_or(false)
}

///|
/// Verify a signature and return an error for malformed public inputs.
pub fn verify_result(
  public_key : Array[UInt],
  message : Array[UInt],
  signature : Array[UInt],
) -> Result[Bool, String] {
  match validate_byte_values(message, "message") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  match validate_bytes(public_key, 32, "public key") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  match validate_bytes(signature, 64, "signature") {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let r_encoded = slice_bytes(signature, 0, 32)
  let s_bytes = slice_bytes(signature, 32, 64)
  let s = bytes_le_to_bigint(s_bytes)
  if s >= l {
    return Ok(false)
  }
  let a = match decode_point(public_key) {
    Err(message) => return Err(message)
    Ok(point) => point
  }
  let r = match decode_point(r_encoded) {
    Err(message) => return Err(message)
    Ok(point) => point
  }
  let k = modl(
    bytes_le_to_bigint(sha512(concat3(r_encoded, public_key, message))),
  )
  let left = base_point_mul(s)
  let right = extended_add(
    extended_from_affine(r),
    extended_mul(k, extended_from_affine(a)),
  )
  Ok(extended_equal(left, right))
}
