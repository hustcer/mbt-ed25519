///|
test "verify_report formats successful verification" {
  @test.assert_eq(verify_report(Ok(true)), (true, "ok"))
}

///|
test "verify_report formats invalid signature" {
  @test.assert_eq(verify_report(Ok(false)), (false, "invalid"))
}

///|
test "verify_report preserves malformed input error" {
  @test.assert_eq(
    verify_report(Err("public key is not in the prime-order subgroup")),
    (false, "public key is not in the prime-order subgroup"),
  )
}
