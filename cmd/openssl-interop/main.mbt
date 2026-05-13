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
fn hex_to_bytes(input : String) -> Bytes {
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
fn hex_nibble(value : Int) -> String {
  match value {
    0 => "0"
    1 => "1"
    2 => "2"
    3 => "3"
    4 => "4"
    5 => "5"
    6 => "6"
    7 => "7"
    8 => "8"
    9 => "9"
    10 => "a"
    11 => "b"
    12 => "c"
    13 => "d"
    14 => "e"
    15 => "f"
    _ => abort("invalid nibble")
  }
}

///|
fn bytes_to_hex(bytes : Bytes) -> String {
  let out = StringBuilder::new(size_hint=bytes.length() * 2)
  for byte in bytes {
    let v = byte.to_int()
    out.write_string(hex_nibble(v >> 4))
    out.write_string(hex_nibble(v & 15))
  }
  out.to_string()
}

///|
fn arg(matches : @argparse.Matches, name : String) -> String {
  match matches.values.get(name) {
    Some([value]) => value
    _ => abort("missing argument \{name}")
  }
}

///|
fn main {
  let command = @argparse.Command::new(
    "openssl-interop",
    positionals=[
      @argparse.PositionArg::new("seed_hex"),
      @argparse.PositionArg::new("message_hex"),
      @argparse.PositionArg::new("openssl_public_hex"),
      @argparse.PositionArg::new("openssl_signature_hex"),
    ],
    about="Compute Ed25519 public key/signature and verify OpenSSL vector",
  )
  let matches = command.parse() catch {
    err => {
      println(err.to_string())
      abort("argument parsing failed")
    }
  }
  let seed = hex_to_bytes(arg(matches, "seed_hex"))
  let message = hex_to_bytes(arg(matches, "message_hex"))
  let openssl_public = hex_to_bytes(arg(matches, "openssl_public_hex"))
  let openssl_signature = hex_to_bytes(arg(matches, "openssl_signature_hex"))
  let moon_public = @ed25519.derive_public_key(seed).unwrap()
  let moon_signature = @ed25519.sign(seed, message).unwrap()
  println("moon_public_hex=\{bytes_to_hex(moon_public)}")
  println("moon_signature_hex=\{bytes_to_hex(moon_signature)}")
  println(
    "moon_verifies_openssl_signature=\{@ed25519.verify(openssl_public, message, openssl_signature)}",
  )
  println(
    "moon_verifies_moon_signature=\{@ed25519.verify(moon_public, message, moon_signature)}",
  )
}
