describe("mtev_b32", function()

  it("should load ffi", function()
    assert.truthy(mtev ~= nil)
  end)

  it("A == decode(encode(A))", function()
    local str = ""
    local buf = charstar(1608)
    local buf2 = charstar(1001)
    for i=1,1000 do
      str = str .. "x"
     
      local rv = mtev.mtev_b32_encode(str, string.len(str), buf, 1608)
      assert.is_true(rv > 0 and rv <= 1608)
      local rv = mtev.mtev_b32_decode(buf, rv, buf2, 1001)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

  it("encode to short buffer", function()
    local str = "This is a string"
    local buf_too_small = charstar(10)
    local rv = mtev.mtev_b32_encode(str, string.len(str), buf_too_small, 10)
    assert.is_true(rv == 0)
  end)

  it("decode to short buffer", function()
    local str = "KRUGS4ZANFZSAYJAON2HE2LOM4======="
    local buf = charstar(str)
    local buf_too_small = charstar(20)
    local rv = mtev.mtev_b32_decode(buf, string.len(str), buf_too_small, 19)
    assert.is_true(rv == 0)
    local rv = mtev.mtev_b32_decode(buf, string.len(str), buf_too_small, 20)
    assert.are.equal(rv, 16)
  end)
end)
