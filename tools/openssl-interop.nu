#!/usr/bin/env nu

def fail [message: string] {
  error make {msg: $message}
}

def ensure-ok [label: string, result: record]: nothing -> nothing {
  if $result.exit_code != 0 {
    let stderr = ($result.stderr | str trim)
    fail $'($label) failed: ($stderr)'
  }
}

def assert-eq [label: string, expected: string, actual: string]: nothing -> nothing {
  if $expected != $actual {
    fail $'($label) mismatch\nexpected: ($expected)\nactual:   ($actual)'
  }
}

def assert-true [label: string, value: string]: nothing -> nothing {
  if $value != 'true' {
    fail $'($label) expected true, got ($value)'
  }
}

def assert-false [label: string, value: string]: nothing -> nothing {
  if $value != 'false' {
    fail $'($label) expected false, got ($value)'
  }
}

def assert-failure [label: string, result: record]: nothing -> nothing {
  if $result.exit_code == 0 {
    fail $'($label) was expected to fail but succeeded'
  }
}

def file-hex [path: path]: nothing -> string {
  open --raw $path | encode hex | str trim | str downcase
}

def extract-prefixed-hex [
  label: string
  input_hex: string
  prefix: string
  byte_count: int
]: nothing -> string {
  let expected_len = (($prefix | str length) + ($byte_count * 2))
  let actual_len = ($input_hex | str length)
  if $actual_len != $expected_len {
    fail $'($label) DER length mismatch: expected ($expected_len) hex chars, got ($actual_len)'
  }
  if not ($input_hex | str starts-with $prefix) {
    fail $'($label) DER prefix mismatch'
  }
  $input_hex | str substring ($prefix | str length)..
}

def extract-seed-hex [private_der_hex: string]: nothing -> string {
  extract-prefixed-hex 'OpenSSL Ed25519 private key' $private_der_hex '302e020100300506032b657004220420' 32
}

def extract-public-key-hex [public_der_hex: string]: nothing -> string {
  extract-prefixed-hex 'OpenSSL Ed25519 public key' $public_der_hex '302a300506032b6570032100' 32
}

def parse-key-value-output [output: string]: nothing -> record {
  $output
  | lines
  | where {|line| ($line | str contains '=') }
  | split column '=' key value
  | reduce --fold {} {|row, acc| $acc | upsert $row.key $row.value }
}

def to-hex-nibble [n: int]: nothing -> string {
  if $n < 10 {
    $n | into string
  } else {
    ['a' 'b' 'c' 'd' 'e' 'f'] | get ($n - 10)
  }
}

# Flip the low bit of the byte at $byte_index in $hex.
def tamper-hex-byte [hex: string, byte_index: int]: nothing -> string {
  let char_index = ($byte_index * 2)
  let byte_hex = ($hex | str substring $char_index..<($char_index + 2))
  let new_byte = (($byte_hex | into int --radix 16) | bits xor 1)
  let new_byte_hex = ((to-hex-nibble ($new_byte // 16)) + (to-hex-nibble ($new_byte mod 16)))
  ($hex | str substring ..<$char_index) + $new_byte_hex + ($hex | str substring ($char_index + 2)..)
}

# Wrap 32-byte raw seed into PKCS#8 Ed25519 PrivateKeyInfo DER.
def wrap-private-key-der [seed_hex: string]: nothing -> string {
  '302e020100300506032b657004220420' + $seed_hex
}

# Wrap 32-byte raw pubkey into Ed25519 SubjectPublicKeyInfo DER.
def wrap-public-key-der [pk_hex: string]: nothing -> string {
  '302a300506032b6570032100' + $pk_hex
}

def save-hex-binary [path: path, hex: string]: nothing -> nothing {
  $hex | decode hex | save -f $path
}

# Build a deterministic binary message of length $n. byte[i] = i mod 256, so
# lengths >= 1 include NUL, lengths >= 128 include the 0x80 high-bit boundary,
# and lengths >= 256 cover every byte value.
def gen-binary-message [n: int]: nothing -> binary {
  mut acc = 0x[]
  for i in 0..<$n {
    let b = ($i mod 256)
    let b_bin = ((to-hex-nibble ($b // 16)) + (to-hex-nibble ($b mod 16)) | decode hex)
    $acc = ($acc | bytes add $b_bin)
  }
  $acc
}

# Generate an OpenSSL Ed25519 keypair into $case_dir. Returns paths and key bytes.
def openssl-genpkey-in [case_dir: path]: nothing -> record {
  let key_pem = ($case_dir | path join 'key.pem')
  let key_der = ($case_dir | path join 'key.der')
  let pub_pem = ($case_dir | path join 'pub.pem')
  let pub_der = ($case_dir | path join 'pub.der')
  ensure-ok 'openssl genpkey' (
    ^openssl genpkey -algorithm Ed25519 -out $key_pem | complete
  )
  ensure-ok 'openssl private DER export' (
    ^openssl pkey -in $key_pem -outform DER -out $key_der | complete
  )
  ensure-ok 'openssl public PEM export' (
    ^openssl pkey -in $key_pem -pubout -out $pub_pem | complete
  )
  ensure-ok 'openssl public DER export' (
    ^openssl pkey -in $key_pem -pubout -outform DER -out $pub_der | complete
  )
  let seed_hex = (extract-seed-hex (file-hex $key_der))
  let openssl_public_hex = (extract-public-key-hex (file-hex $pub_der))
  {
    key_pem: $key_pem
    key_der: $key_der
    pub_pem: $pub_pem
    pub_der: $pub_der
    seed_hex: $seed_hex
    openssl_public_hex: $openssl_public_hex
  }
}

# Load an OpenSSL keypair from a caller-supplied raw seed.
def openssl-load-seed-in [case_dir: path, seed_hex: string]: nothing -> record {
  let key_der = ($case_dir | path join 'key.der')
  let key_pem = ($case_dir | path join 'key.pem')
  let pub_pem = ($case_dir | path join 'pub.pem')
  let pub_der = ($case_dir | path join 'pub.der')
  save-hex-binary $key_der (wrap-private-key-der $seed_hex)
  ensure-ok 'openssl pkey load seed DER' (
    ^openssl pkey -in $key_der -inform DER -out $key_pem | complete
  )
  ensure-ok 'openssl public PEM export' (
    ^openssl pkey -in $key_pem -pubout -out $pub_pem | complete
  )
  ensure-ok 'openssl public DER export' (
    ^openssl pkey -in $key_pem -pubout -outform DER -out $pub_der | complete
  )
  let openssl_public_hex = (extract-public-key-hex (file-hex $pub_der))
  {
    key_pem: $key_pem
    key_der: $key_der
    pub_pem: $pub_pem
    pub_der: $pub_der
    seed_hex: $seed_hex
    openssl_public_hex: $openssl_public_hex
  }
}

# Sign a message file with OpenSSL.
def openssl-sign [key_pem: path, message_path: path, signature_path: path]: nothing -> nothing {
  ensure-ok 'openssl sign' (
    ^openssl pkeyutl -sign -rawin -inkey $key_pem -in $message_path -out $signature_path | complete
  )
}

# Verify a message and signature against an OpenSSL public PEM. Returns the
# `complete` record so callers can branch on exit_code.
def openssl-verify [pub_pem: path, message_path: path, signature_path: path]: nothing -> record {
  ^openssl pkeyutl -verify -rawin -pubin -inkey $pub_pem -in $message_path -sigfile $signature_path | complete
}

# Drive the MoonBit interop binary. Returns parsed key=value record with keys
# moon_public_hex, moon_signature_hex, moon_verifies_openssl_signature,
# moon_verifies_moon_signature.
def moon-interop [
  seed_hex: string
  message_hex: string
  openssl_public_hex: string
  openssl_signature_hex: string
]: nothing -> record {
  let moon_result = (
    ^moon run --release cmd/openssl-interop $seed_hex $message_hex $openssl_public_hex $openssl_signature_hex
    | complete
  )
  ensure-ok 'moon openssl-interop' $moon_result
  let moon = (parse-key-value-output $moon_result.stdout)
  if (
    $moon.moon_public_hex? == null or
    $moon.moon_signature_hex? == null or
    $moon.moon_verifies_openssl_signature? == null or
    $moon.moon_verifies_moon_signature? == null
  ) {
    fail $'moon openssl-interop output is incomplete:\n($moon_result.stdout)'
  }
  $moon
}

# Run a full positive interop round (OpenSSL signs + MoonBit signs + each side
# verifies the other). Returns one row per assertion.
def run-positive-round [
  case_dir: path
  case_label: string
  key: record
  message: binary
]: nothing -> list {
  mkdir $case_dir
  let message_path = ($case_dir | path join 'msg.bin')
  let openssl_sig_path = ($case_dir | path join 'openssl.sig')
  let moon_sig_path = ($case_dir | path join 'moon.sig')
  $message | save -f $message_path
  openssl-sign $key.key_pem $message_path $openssl_sig_path

  let message_hex = (file-hex $message_path)
  let openssl_signature_hex = (file-hex $openssl_sig_path)
  let moon = (moon-interop $key.seed_hex $message_hex $key.openssl_public_hex $openssl_signature_hex)

  assert-eq $'($case_label): public key' $key.openssl_public_hex $moon.moon_public_hex
  assert-eq $'($case_label): signature' $openssl_signature_hex $moon.moon_signature_hex
  assert-true $'($case_label): MoonBit verifies OpenSSL signature' $moon.moon_verifies_openssl_signature
  assert-true $'($case_label): MoonBit verifies MoonBit signature' $moon.moon_verifies_moon_signature

  save-hex-binary $moon_sig_path $moon.moon_signature_hex
  ensure-ok $'($case_label): openssl verifies MoonBit signature' (
    openssl-verify $key.pub_pem $message_path $moon_sig_path
  )
  ensure-ok $'($case_label): openssl verifies OpenSSL signature' (
    openssl-verify $key.pub_pem $message_path $openssl_sig_path
  )

  [
    {scenario: $case_label, check: 'public key equality', ok: true}
    {scenario: $case_label, check: 'signature equality', ok: true}
    {scenario: $case_label, check: 'MoonBit verifies OpenSSL signature', ok: true}
    {scenario: $case_label, check: 'OpenSSL verifies MoonBit signature', ok: true}
    {scenario: $case_label, check: 'OpenSSL verifies OpenSSL signature', ok: true}
  ]
}

# Scenario 1: vary message length across SHA-512 block boundaries and binary
# content. One fresh key is reused for every length to amortize genpkey cost.
# Note: 0-byte messages are exercised by `run-external-seed-injection` via the
# RFC 8032 vector-1 signature; OpenSSL's `pkeyutl -sign -rawin` refuses an
# empty input file, so we cannot drive the OpenSSL signing side at size 0.
def run-length-matrix [workdir: path]: nothing -> list {
  let case_dir = ($workdir | path join 'length-matrix')
  mkdir $case_dir
  let key = (openssl-genpkey-in $case_dir)
  # SHA-512 processes 128-byte blocks; for an N-byte message the single-block
  # boundary is at N + 9 <= 128 (length encoding + 0x80 separator), i.e. N <= 119.
  let sizes = [1 2 32 64 111 112 119 120 127 128 129 200 256 1024]
  $sizes | each { |n|
    let label = $'length:($n)B'
    let sub_dir = ($case_dir | path join $'msg-($n)')
    run-positive-round $sub_dir $label $key (gen-binary-message $n)
  } | flatten
}

# Scenario 2: run the basic interop N times with a fresh OpenSSL key per
# iteration. Catches occasional non-determinism or rare-scalar issues.
def run-multi-iteration [workdir: path, iterations: int]: nothing -> list {
  let case_dir = ($workdir | path join 'multi-iter')
  mkdir $case_dir
  let default_message = ('s8fy-license:{"customerId":"self","expiresAt":"2027-05-05","product":"s8fy-viewer"}' | encode utf-8)
  0..<$iterations | each { |i|
    let sub_dir = ($case_dir | path join $'iter-($i)')
    mkdir $sub_dir
    let key = (openssl-genpkey-in $sub_dir)
    run-positive-round $sub_dir $'multi-iter#($i)' $key $default_message
  } | flatten
}

# Scenario 3: tamper one byte in message / R / S, and assert both OpenSSL and
# MoonBit reject the tampered tuple.
def run-tamper-rejection [workdir: path]: nothing -> list {
  let case_dir = ($workdir | path join 'tamper')
  mkdir $case_dir
  let key = (openssl-genpkey-in $case_dir)
  let message = ('tamper-test-message' | encode utf-8)
  let message_path = ($case_dir | path join 'msg.bin')
  let openssl_sig_path = ($case_dir | path join 'openssl.sig')
  $message | save -f $message_path
  openssl-sign $key.key_pem $message_path $openssl_sig_path

  let message_hex = (file-hex $message_path)
  let openssl_signature_hex = (file-hex $openssl_sig_path)

  # Sanity: positive verification works before tampering.
  let positive_moon = (moon-interop $key.seed_hex $message_hex $key.openssl_public_hex $openssl_signature_hex)
  assert-true 'tamper baseline: MoonBit verifies' $positive_moon.moon_verifies_openssl_signature
  ensure-ok 'tamper baseline: OpenSSL verifies' (
    openssl-verify $key.pub_pem $message_path $openssl_sig_path
  )

  let variants = [
    {label: 'tamper:message-byte0', target: 'message', byte: 0}
    {label: 'tamper:R-byte0',       target: 'r',       byte: 0}
    {label: 'tamper:S-byte0',       target: 's',       byte: 32}
  ]

  $variants | each { |v|
    let tampered_message_hex = (
      if $v.target == 'message' { tamper-hex-byte $message_hex $v.byte } else { $message_hex }
    )
    let tampered_sig_hex = (
      if $v.target == 'message' { $openssl_signature_hex } else { tamper-hex-byte $openssl_signature_hex $v.byte }
    )
    let tampered_msg_path = ($case_dir | path join $'($v.label)-msg.bin')
    let tampered_sig_path = ($case_dir | path join $'($v.label)-sig.bin')
    save-hex-binary $tampered_msg_path $tampered_message_hex
    save-hex-binary $tampered_sig_path $tampered_sig_hex

    let moon = (moon-interop $key.seed_hex $tampered_message_hex $key.openssl_public_hex $tampered_sig_hex)
    assert-false $'($v.label): MoonBit rejects' $moon.moon_verifies_openssl_signature
    assert-failure $'($v.label): OpenSSL rejects' (
      openssl-verify $key.pub_pem $tampered_msg_path $tampered_sig_path
    )

    [
      {scenario: 'tamper', check: $'($v.label): MoonBit rejects', ok: true}
      {scenario: 'tamper', check: $'($v.label): OpenSSL rejects', ok: true}
    ]
  } | flatten
}

# Scenario 4: take the MoonBit-derived pubkey bytes, wrap into a fresh DER
# SubjectPublicKeyInfo, load with OpenSSL, and verify the MoonBit signature
# using only that reconstructed PEM. Proves MoonBit pubkey is byte-identical
# and OpenSSL-loadable independent of OpenSSL's own export path.
def run-reverse-pubkey-load [workdir: path]: nothing -> list {
  let case_dir = ($workdir | path join 'reverse-pubkey')
  mkdir $case_dir
  let key = (openssl-genpkey-in $case_dir)
  let message = ('reverse-pubkey-message' | encode utf-8)
  let message_path = ($case_dir | path join 'msg.bin')
  $message | save -f $message_path
  let message_hex = (file-hex $message_path)

  # Use MoonBit to compute pubkey + signature; OpenSSL signature is unused but
  # the interop binary requires it as input, so pass any well-formed value.
  let openssl_sig_path = ($case_dir | path join 'openssl.sig')
  openssl-sign $key.key_pem $message_path $openssl_sig_path
  let openssl_signature_hex = (file-hex $openssl_sig_path)

  let moon = (moon-interop $key.seed_hex $message_hex $key.openssl_public_hex $openssl_signature_hex)
  assert-eq 'reverse-pubkey: pubkey equality' $key.openssl_public_hex $moon.moon_public_hex

  let reconstructed_der_path = ($case_dir | path join 'moon-pub.der')
  let reconstructed_pem_path = ($case_dir | path join 'moon-pub.pem')
  save-hex-binary $reconstructed_der_path (wrap-public-key-der $moon.moon_public_hex)
  ensure-ok 'reverse-pubkey: openssl loads reconstructed DER' (
    ^openssl pkey -pubin -in $reconstructed_der_path -inform DER -pubout -out $reconstructed_pem_path | complete
  )

  let moon_sig_path = ($case_dir | path join 'moon.sig')
  save-hex-binary $moon_sig_path $moon.moon_signature_hex
  ensure-ok 'reverse-pubkey: openssl verifies via reconstructed PEM' (
    openssl-verify $reconstructed_pem_path $message_path $moon_sig_path
  )

  [
    {scenario: 'reverse-pubkey', check: 'MoonBit pubkey loads in OpenSSL via DER wrap', ok: true}
    {scenario: 'reverse-pubkey', check: 'OpenSSL verifies MoonBit signature via reconstructed PEM', ok: true}
  ]
}

# Scenario 5: feed a known seed (RFC 8032 test vector 1) into OpenSSL by
# building a DER PrivateKeyInfo from the raw seed. Verify OpenSSL derives the
# RFC 8032 vector-1 pubkey from this seed, then verify MoonBit produces the
# RFC 8032 vector-1 signature for the empty message under the same seed. The
# empty-message signature is generated by MoonBit because `openssl pkeyutl
# -sign -rawin` refuses an empty input file. Finally, run a full positive
# round on a small non-empty payload so OpenSSL and MoonBit cross-check on
# the injected seed.
def run-external-seed-injection [workdir: path]: nothing -> list {
  let case_dir = ($workdir | path join 'external-seed')
  mkdir $case_dir
  let rfc_seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  let rfc_pubkey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
  let rfc_signature_empty = (
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
      + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
  )

  let key = (openssl-load-seed-in $case_dir $rfc_seed)
  assert-eq 'external-seed: pubkey matches RFC 8032 vector 1' $rfc_pubkey $key.openssl_public_hex

  # Use moon-interop to sign the empty message under the RFC seed. The
  # openssl_* arguments to moon-interop are irrelevant for the equality check;
  # we feed the known-good RFC signature so moon_verifies_openssl_signature
  # stays true (positive sanity).
  let moon_empty = (moon-interop $rfc_seed '' $rfc_pubkey $rfc_signature_empty)
  assert-eq 'external-seed: MoonBit pubkey matches RFC vector' $rfc_pubkey $moon_empty.moon_public_hex
  assert-eq 'external-seed: MoonBit signature matches RFC vector' $rfc_signature_empty $moon_empty.moon_signature_hex
  assert-true 'external-seed: MoonBit verifies RFC empty signature' $moon_empty.moon_verifies_openssl_signature

  # Run a positive cross-verify round on a short non-empty payload so the
  # OpenSSL CLI sign/verify path also exercises the injected seed.
  let payload = ('external-seed-roundtrip' | encode utf-8)
  let positive_rows = (run-positive-round ($case_dir | path join 'roundtrip') 'external-seed:roundtrip' $key $payload)

  $positive_rows | append [
    {scenario: 'external-seed', check: 'OpenSSL pubkey matches RFC 8032 vector 1', ok: true}
    {scenario: 'external-seed', check: 'MoonBit signature matches RFC 8032 vector 1 (empty message)', ok: true}
  ]
}

# Scenario 6: tamper the verifying public key itself (not the signature). A
# one-byte flip in a 32-byte y-coordinate either yields another valid curve
# point (decode succeeds, signature math fails) or an invalid encoding (decode
# fails). Either outcome must surface as a verification rejection on both
# sides; this scenario exercises the public-key decode path that none of the
# message/R/S tamper variants reach.
def run-pubkey-tamper-rejection [workdir: path]: nothing -> list {
  let case_dir = ($workdir | path join 'pubkey-tamper')
  mkdir $case_dir
  let key = (openssl-genpkey-in $case_dir)
  let message = ('pubkey-tamper-message' | encode utf-8)
  let message_path = ($case_dir | path join 'msg.bin')
  let openssl_sig_path = ($case_dir | path join 'openssl.sig')
  $message | save -f $message_path
  openssl-sign $key.key_pem $message_path $openssl_sig_path
  let message_hex = (file-hex $message_path)
  let openssl_signature_hex = (file-hex $openssl_sig_path)

  # Sanity: untampered pubkey verifies.
  let baseline = (moon-interop $key.seed_hex $message_hex $key.openssl_public_hex $openssl_signature_hex)
  assert-true 'pubkey-tamper baseline: MoonBit verifies' $baseline.moon_verifies_openssl_signature
  ensure-ok 'pubkey-tamper baseline: OpenSSL verifies' (
    openssl-verify $key.pub_pem $message_path $openssl_sig_path
  )

  # Byte 0 is low byte of y; byte 31 holds high y bits and the x-sign bit, so
  # flipping its low bit still lands inside the y-coordinate range. Both
  # positions exercise the decode-then-verify path on each side.
  let variants = [
    {label: 'pubkey-tamper:byte0',  byte: 0}
    {label: 'pubkey-tamper:byte31', byte: 31}
  ]

  $variants | each { |v|
    let tampered_pk_hex = (tamper-hex-byte $key.openssl_public_hex $v.byte)
    let tampered_der_path = ($case_dir | path join $'($v.label).der')
    let tampered_pem_path = ($case_dir | path join $'($v.label).pem')
    save-hex-binary $tampered_der_path (wrap-public-key-der $tampered_pk_hex)

    # OpenSSL: a load failure is a rejection. If the tampered SPKI loads
    # successfully (valid curve point), verify must still fail.
    let load_result = (
      ^openssl pkey -pubin -in $tampered_der_path -inform DER -pubout -out $tampered_pem_path
      | complete
    )
    let openssl_rejects = if $load_result.exit_code != 0 {
      true
    } else {
      let verify_result = (openssl-verify $tampered_pem_path $message_path $openssl_sig_path)
      $verify_result.exit_code != 0
    }
    if not $openssl_rejects {
      fail $'($v.label): OpenSSL accepted signature under tampered pubkey'
    }

    # MoonBit: verify path silently returns false whether decode rejects the
    # tampered pubkey or the curve math rejects the signature afterwards.
    let moon = (moon-interop $key.seed_hex $message_hex $tampered_pk_hex $openssl_signature_hex)
    assert-false $'($v.label): MoonBit rejects' $moon.moon_verifies_openssl_signature

    [
      {scenario: 'pubkey-tamper', check: $'($v.label): MoonBit rejects', ok: true}
      {scenario: 'pubkey-tamper', check: $'($v.label): OpenSSL rejects', ok: true}
    ]
  } | flatten
}

def main [
  --iterations (-n): int = 4
  --keep-temp
]: nothing -> table {
  let temp_dir = (mktemp -d)
  try {
    let openssl_version = (^openssl version | complete)
    ensure-ok 'openssl version' $openssl_version

    let rows = (
      []
      | append (run-length-matrix $temp_dir)
      | append (run-multi-iteration $temp_dir $iterations)
      | append (run-tamper-rejection $temp_dir)
      | append (run-pubkey-tamper-rejection $temp_dir)
      | append (run-reverse-pubkey-load $temp_dir)
      | append (run-external-seed-injection $temp_dir)
    )

    if not $keep_temp {
      rm -rf $temp_dir
    } else {
      print $'kept temp dir: ($temp_dir)'
    }

    $rows | table -t light
  } catch {|err|
    if not $keep_temp {
      rm -rf $temp_dir
    }
    fail ($err.msg? | default ($err | to nuon))
  }
}
