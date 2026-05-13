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

def main [
  --message (-m): string = 's8fy-license:{"customerId":"self","expiresAt":"2027-05-05","product":"s8fy-viewer"}'
  --keep-temp
]: nothing -> table {
  let temp_dir = (mktemp -d)
  let key_pem = ($temp_dir | path join 'ed25519.key.pem')
  let key_der = ($temp_dir | path join 'ed25519.key.der')
  let public_pem = ($temp_dir | path join 'ed25519.pub.pem')
  let public_der = ($temp_dir | path join 'ed25519.pub.der')
  let message_path = ($temp_dir | path join 'message.bin')
  let openssl_signature_path = ($temp_dir | path join 'openssl.sig')
  let moon_signature_path = ($temp_dir | path join 'moon.sig')

  try {
    let openssl_version = (^openssl version | complete)
    ensure-ok 'openssl version' $openssl_version

    $message | save -f $message_path

    ensure-ok 'openssl genpkey' (
      ^openssl genpkey -algorithm Ed25519 -out $key_pem | complete
    )
    ensure-ok 'openssl private DER export' (
      ^openssl pkey -in $key_pem -outform DER -out $key_der | complete
    )
    ensure-ok 'openssl public PEM export' (
      ^openssl pkey -in $key_pem -pubout -out $public_pem | complete
    )
    ensure-ok 'openssl public DER export' (
      ^openssl pkey -in $key_pem -pubout -outform DER -out $public_der | complete
    )
    ensure-ok 'openssl sign' (
      ^openssl pkeyutl -sign -rawin -inkey $key_pem -in $message_path -out $openssl_signature_path | complete
    )

    let seed_hex = (extract-seed-hex (file-hex $key_der))
    let message_hex = (file-hex $message_path)
    let openssl_public_hex = (extract-public-key-hex (file-hex $public_der))
    let openssl_signature_hex = (file-hex $openssl_signature_path)

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

    assert-eq 'public key' $openssl_public_hex $moon.moon_public_hex
    assert-eq 'signature' $openssl_signature_hex $moon.moon_signature_hex
    assert-true 'MoonBit verifies OpenSSL signature' $moon.moon_verifies_openssl_signature
    assert-true 'MoonBit verifies MoonBit signature' $moon.moon_verifies_moon_signature

    $moon.moon_signature_hex | decode hex | save -f $moon_signature_path
    ensure-ok 'openssl verify MoonBit signature' (
      ^openssl pkeyutl -verify -rawin -pubin -inkey $public_pem -in $message_path -sigfile $moon_signature_path | complete
    )
    ensure-ok 'openssl verify OpenSSL signature' (
      ^openssl pkeyutl -verify -rawin -pubin -inkey $public_pem -in $message_path -sigfile $openssl_signature_path | complete
    )

    let report = [
      {check: 'public key equality', ok: true}
      {check: 'signature equality', ok: true}
      {check: 'MoonBit verifies OpenSSL signature', ok: true}
      {check: 'OpenSSL verifies MoonBit signature', ok: true}
      {check: 'OpenSSL verifies OpenSSL signature', ok: true}
    ]

    if not $keep_temp {
      rm -rf $temp_dir
    } else {
      print $'kept temp dir: ($temp_dir)'
    }

    $report | table -t light
  } catch {|err|
    if not $keep_temp {
      rm -rf $temp_dir
    }
    fail ($err.msg? | default ($err | to nuon))
  }
}
