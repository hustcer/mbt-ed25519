#!/usr/bin/env nu

const source_revision = 'b61843a9a5115bb758134b6a1f5d5e502d445342'
const source_sha256 = '70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00'
const source_url = 'https://raw.githubusercontent.com/C2SP/wycheproof/b61843a9a5115bb758134b6a1f5d5e502d445342/testvectors_v1/ed25519_test.json'
const output_path = path self ../wycheproof_test.mbt

def fail [message: string] {
  error make {msg: $message}
}

def moonbit-string [value: string]: nothing -> string {
  $value | to json --raw
}

def validate-source [source: record]: nothing -> nothing {
  if $source.algorithm? != 'EDDSA' {
    fail $'Unexpected Wycheproof algorithm: ($source.algorithm?)'
  }
  if $source.schema? != 'eddsa_verify_schema_v1.json' {
    fail $'Unexpected Wycheproof schema: ($source.schema?)'
  }
  let cases = ($source.testGroups? | default [] | get tests | flatten)
  if ($cases | length) != $source.numberOfTests? {
    fail $'Wycheproof test count does not match numberOfTests: ($cases | length)'
  }
  let unsupported = ($cases | where result not-in [valid invalid])
  if not ($unsupported | is-empty) {
    fail 'Wycheproof source contains unsupported result values'
  }
}

def render-case [case: record]: nothing -> list<string> {
  let expected_valid = if $case.result == 'valid' { 'true' } else { 'false' }
  [
    '        {'
    $'          tc_id: ($case.tcId),'
    $'          message_hex: (moonbit-string $case.msg),'
    $'          signature_hex: (moonbit-string $case.sig),'
    $'          expected_valid: ($expected_valid),'
    '        },'
  ]
}

def render-group [group: record]: nothing -> list<string> {
  let cases = ($group.tests | each {|case| render-case $case } | flatten)
  [
    '    {'
    $'      public_key_hex: (moonbit-string $group.publicKey.pk),'
    '      cases: ['
    ...$cases
    '      ],'
    '    },'
  ]
}

def render-test [source: record]: nothing -> string {
  let groups = ($source.testGroups | each {|group| render-group $group } | flatten)
  let lines = [
    '///|'
    '/// Generated from Project Wycheproof Ed25519 v1 verification vectors.'
    $'/// Source revision: ($source_revision)'
    $'/// Source SHA-256: ($source_sha256)'
    '/// Source path: testvectors_v1/ed25519_test.json'
    '/// License: Apache-2.0, Copyright 2016-2026 The Wycheproof Authors.'
    'priv struct WycheproofCase {'
    '  tc_id : Int'
    '  message_hex : String'
    '  signature_hex : String'
    '  expected_valid : Bool'
    '}'
    ''
    '///|'
    'priv struct WycheproofGroup {'
    '  public_key_hex : String'
    '  cases : Array[WycheproofCase]'
    '}'
    ''
    '///|'
    'fn wycheproof_hex_value(c : UInt16) -> UInt {'
    '  if c >= 48 && c <= 57 {'
    '    c.to_uint() - 48U'
    '  } else if c >= 97 && c <= 102 {'
    '    c.to_uint() - 97U + 10U'
    '  } else if c >= 65 && c <= 70 {'
    '    c.to_uint() - 65U + 10U'
    '  } else {'
    '    abort("invalid Wycheproof hex")'
    '  }'
    '}'
    ''
    '///|'
    'fn wycheproof_hex(input : String) -> Bytes {'
    '  if input.length() % 2 != 0 {'
    '    abort("Wycheproof hex input must have even length")'
    '  }'
    '  Bytes::makei(input.length() / 2, fn(i) {'
    '    let hi = wycheproof_hex_value(input[2 * i])'
    '    let lo = wycheproof_hex_value(input[2 * i + 1])'
    '    ((hi << 4) | lo).to_byte()'
    '  })'
    '}'
    ''
    '///|'
    'fn wycheproof_groups() -> Array[WycheproofGroup] {'
    '  ['
    ...$groups
    '  ]'
    '}'
    ''
    '///|'
    'test "Project Wycheproof Ed25519 v1 corpus at pinned revision" {'
    '  let mut seen = 0'
    '  for group in wycheproof_groups() {'
    '    let public_key = wycheproof_hex(group.public_key_hex)'
    '    try @ed25519.VerifyingKey::from_public_key(public_key) catch {'
    '      err =>'
    '        for case in group.cases {'
    '          if case.expected_valid {'
    '            fail('
    '              "Wycheproof tcId \{case.tc_id} expected valid but public key was rejected: \{err}",'
    '            )'
    '          }'
    '          seen += 1'
    '        }'
    '    } noraise {'
    '      verifying_key =>'
    '        for case in group.cases {'
    '          let actual = verifying_key.verify('
    '            wycheproof_hex(case.message_hex),'
    '            wycheproof_hex(case.signature_hex),'
    '          )'
    '          if actual != case.expected_valid {'
    '            fail('
    '              "Wycheproof tcId \{case.tc_id}: expected valid=\{case.expected_valid}, got \{actual}",'
    '            )'
    '          }'
    '          seen += 1'
    '        }'
    '    }'
    '  }'
    $"  @test.assert_eq\(seen, ($source.numberOfTests))"
    '}'
  ]
  ($lines | str join (char nl)) + (char nl)
}

def main [
  --check
]: nothing -> nothing {
  let raw = (http get --raw $source_url)
  let actual_sha256 = ($raw | hash sha256)
  if $actual_sha256 != $source_sha256 {
    fail $'Wycheproof source digest mismatch: expected ($source_sha256), got ($actual_sha256)'
  }
  let source = ($raw | from json)
  validate-source $source
  let rendered = (render-test $source)
  if $check {
    if not ($output_path | path exists) {
      fail $'Generated Wycheproof test is missing: ($output_path)'
    }
    if (open --raw $output_path) != $rendered {
      fail 'Generated Wycheproof test is stale; run nu tools/update-wycheproof.nu'
    }
  } else {
    $rendered | save --force $output_path
    print $'Updated ($output_path) from Wycheproof revision ($source_revision)'
  }
}
