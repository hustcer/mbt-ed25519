#!/usr/bin/env nu

const repo_root = path self ..
const node_driver = path self node-interop.mjs

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

def parse-key-value-output [output: string]: nothing -> record {
  $output
  | lines
  | where {|line| ($line | str contains '=') }
  | split column '=' key value
  | reduce --fold {} {|row, acc| $acc | upsert $row.key $row.value }
}

def require-fields [label: string, record: record, fields: list<string>]: nothing -> nothing {
  let missing = ($fields | where {|field| ($record | get -o $field) == null })
  if not ($missing | is-empty) {
    fail $'($label) output is missing fields: ($missing | str join ", ")'
  }
}

def node-sign [node_bin: path, seed_hex: string, message_hex: string]: nothing -> record {
  let result = (run-external $node_bin $node_driver sign $seed_hex $message_hex | complete)
  ensure-ok 'node sign' $result
  let parsed = (parse-key-value-output $result.stdout)
  require-fields 'node sign' $parsed [
    node_public_hex
    node_signature_hex
    node_verifies_node_signature
  ]
  $parsed
}

def node-verify [
  node_bin: path
  public_key_hex: string
  message_hex: string
  signature_hex: string
]: nothing -> string {
  let result = (
    run-external $node_bin $node_driver verify $public_key_hex $message_hex $signature_hex
    | complete
  )
  ensure-ok 'node verify' $result
  let parsed = (parse-key-value-output $result.stdout)
  require-fields 'node verify' $parsed [node_verifies_signature]
  $parsed.node_verifies_signature
}

def moon-interop [
  seed_hex: string
  message_hex: string
  public_key_hex: string
  signature_hex: string
]: nothing -> record {
  let result = (
    ^moon -C $repo_root run --release cmd/openssl-interop $seed_hex $message_hex $public_key_hex $signature_hex
    | complete
  )
  ensure-ok 'moon interop' $result
  let parsed = (parse-key-value-output $result.stdout)
  require-fields 'moon interop' $parsed [
    moon_public_hex
    moon_signature_hex
    moon_verifies_openssl_signature
    moon_verifies_moon_signature
    moon_verify_openssl_result
  ]
  $parsed
}

def to-hex-nibble [n: int]: nothing -> string {
  if $n < 10 {
    $n | into string
  } else {
    [a b c d e f] | get ($n - 10)
  }
}

def gen-binary-message [n: int]: nothing -> binary {
  mut acc = 0x[]
  for i in 0..<$n {
    let b = ($i mod 256)
    let byte = ((to-hex-nibble ($b // 16)) + (to-hex-nibble ($b mod 16)) | decode hex)
    $acc = ($acc | bytes add $byte --end)
  }
  $acc
}

def run-positive-round [
  node_bin: path
  label: string
  seed_hex: string
  message: binary
]: nothing -> list<record> {
  let message_hex = ($message | encode hex | str lowercase)
  let node = (node-sign $node_bin $seed_hex $message_hex)
  assert-true $'($label): Node verifies Node signature' $node.node_verifies_node_signature
  let moon = (
    moon-interop $seed_hex $message_hex $node.node_public_hex $node.node_signature_hex
  )
  assert-eq $'($label): public key' $node.node_public_hex $moon.moon_public_hex
  assert-eq $'($label): signature' $node.node_signature_hex $moon.moon_signature_hex
  assert-true $'($label): MoonBit verifies Node signature' $moon.moon_verifies_openssl_signature
  assert-true $'($label): MoonBit verifies MoonBit signature' $moon.moon_verifies_moon_signature
  assert-true $'($label): Node verifies MoonBit signature' (
    node-verify $node_bin $node.node_public_hex $message_hex $moon.moon_signature_hex
  )
  [
    {scenario: $label, check: 'public key equality', ok: true}
    {scenario: $label, check: 'signature equality', ok: true}
    {scenario: $label, check: 'MoonBit verifies Node signature', ok: true}
    {scenario: $label, check: 'Node verifies MoonBit signature', ok: true}
    {scenario: $label, check: 'self verification', ok: true}
  ]
}

def run-rfc8032-vectors [node_bin: path]: nothing -> list<record> {
  let vectors = [
    {
      id: 1
      seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
      public_key: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
      message: ''
      signature: ('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    }
    {
      id: 2
      seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
      public_key: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
      message: '72'
      signature: ('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' + '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
    }
    {
      id: 3
      seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
      public_key: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'
      message: 'af82'
      signature: ('6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' + '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a')
    }
  ]
  $vectors | each {|vector|
    let label = $'rfc8032#($vector.id)'
    let node = (node-sign $node_bin $vector.seed $vector.message)
    assert-eq $'($label): public key' $vector.public_key $node.node_public_hex
    assert-eq $'($label): signature' $vector.signature $node.node_signature_hex
    let rows = (run-positive-round $node_bin $label $vector.seed ($vector.message | decode hex))
    $rows | append [
      {scenario: $label, check: 'Node public key matches RFC 8032', ok: true}
      {scenario: $label, check: 'Node signature matches RFC 8032', ok: true}
    ]
  } | flatten
}

def run-length-matrix [node_bin: path]: nothing -> list<record> {
  let seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  let sizes = [0 1 2 32 64 111 112 119 120 127 128 129 200 256 1024]
  $sizes | each {|n|
    run-positive-round $node_bin $'length:($n)B' $seed (gen-binary-message $n)
  } | flatten
}

def run-cross-message-rejection [
  node_bin: path
  label: string
  seed_hex: string
  public_key_hex: string
  message: binary
  signature_hex: string
]: nothing -> list<record> {
  let message_hex = ($message | encode hex | str lowercase)
  let moon = (
    moon-interop $seed_hex $message_hex $public_key_hex $signature_hex
  )
  assert-false $'($label): MoonBit rejects' $moon.moon_verifies_openssl_signature
  assert-false $'($label): Node rejects' (
    node-verify $node_bin $public_key_hex $message_hex $signature_hex
  )
  [
    {scenario: 'domain-separation', check: $'($label): MoonBit rejects', ok: true}
    {scenario: 'domain-separation', check: $'($label): Node rejects', ok: true}
  ]
}

def run-domain-separation-mirror [node_bin: path]: nothing -> list<record> {
  let seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  let payload = ('{"schemaVersion":"xdoc-viewer-license/v1","expiresAt":"2027-01-01T00:00:00.000Z"}' | encode utf-8)
  let correct = (
    ('xdoc-viewer-license/v1' | encode utf-8)
    | bytes add 0x[00] --end
    | bytes add $payload --end
  )
  let wrong_context = (
    ('xdoc-cli-license/v1' | encode utf-8)
    | bytes add 0x[00] --end
    | bytes add $payload --end
  )
  let correct_hex = ($correct | encode hex | str lowercase)
  let wrong_context_hex = ($wrong_context | encode hex | str lowercase)
  let payload_hex = ($payload | encode hex | str lowercase)
  let expected_correct_hex = (
    '78646f632d7669657765722d6c6963656e73652f763100' +
    '7b22736368656d6156657273696f6e223a2278646f632d7669657765722d6c6963656e73652f7631222c22657870697265734174223a22323032372d30312d30315430303a30303a30302e3030305a227d'
  )
  assert-eq 'domain-separation: context-NUL-payload bytes' $expected_correct_hex $correct_hex
  let correct_node = (node-sign $node_bin $seed $correct_hex)
  let wrong_node = (node-sign $node_bin $seed $wrong_context_hex)
  let raw_node = (node-sign $node_bin $seed $payload_hex)
  assert-eq 'domain-separation: correct signature' (
    '299933a6e995351f81a657b364d71777aca86b50ea4c6478f0bab574e4812164' +
    '9f810e9f403790085b2e1d472d3446fecefce8e7306dfad096a2af8ba3ba9b09'
  ) $correct_node.node_signature_hex
  assert-eq 'domain-separation: wrong-context signature' (
    'ec562311ea97835c06a87e8285c18ea44d21f43a02439964df743344b5a0558b' +
    '560a86cf35b29e806547931ea37990be9807b464dfe401649867155c06dbf909'
  ) $wrong_node.node_signature_hex
  assert-eq 'domain-separation: raw-payload signature' (
    '5d1040595ed7eb81150ed5384c554e50309d701bbcc04c93baa8e10885d1917f' +
    'c80ee56f38e5a37256a2d70b847f003079d826430e2e2d96d6703f2ad6429a06'
  ) $raw_node.node_signature_hex
  let positive = (run-positive-round $node_bin 'domain-separation:correct' $seed $correct)
  $positive
  | append (
    run-cross-message-rejection $node_bin 'correct-signature-on-wrong-context' $seed $correct_node.node_public_hex $wrong_context $correct_node.node_signature_hex
  )
  | append (
    run-cross-message-rejection $node_bin 'correct-signature-on-raw-payload' $seed $correct_node.node_public_hex $payload $correct_node.node_signature_hex
  )
  | append (
    run-cross-message-rejection $node_bin 'wrong-context-signature-on-correct-input' $seed $correct_node.node_public_hex $correct $wrong_node.node_signature_hex
  )
  | append (
    run-cross-message-rejection $node_bin 'raw-signature-on-correct-input' $seed $correct_node.node_public_hex $correct $raw_node.node_signature_hex
  )
}

def run-driver-boundaries [node_bin: path]: nothing -> list<record> {
  let seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  let public_key = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
  let cases = [
    {label: 'uppercase hex', args: [sign ($seed | str uppercase) '']}
    {label: 'short seed', args: [sign '00' '']}
    {label: 'odd-length message hex', args: [sign $seed '0']}
    {label: 'short signature', args: [verify $public_key '' '00']}
  ]
  $cases | each {|case|
    let result = (run-external $node_bin $node_driver ...$case.args | complete)
    assert-failure $'node adapter: ($case.label)' $result
    {scenario: 'node-adapter', check: $'rejects ($case.label)', ok: true}
  }
}

def main [
  --node-bin: string = 'node'
]: nothing -> table {
  let resolved_node = (
    which $node_bin
    | get 0.path
    | path expand --strict
  )
  let node_version = (run-external $resolved_node '--version' | complete)
  ensure-ok 'node version' $node_version
  let rows = (
    []
    | append (run-rfc8032-vectors $resolved_node)
    | append (run-length-matrix $resolved_node)
    | append (run-domain-separation-mirror $resolved_node)
    | append (run-driver-boundaries $resolved_node)
  )
  $rows | table -t light
}
