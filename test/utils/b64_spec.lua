describe("mtev_b64", function()
  it("A == decode(encode(A))", function()
    local str = ""
    local buf = charstar(1600)
    local buf2 = charstar(1001)
    for i=1,1000 do
      str = str .. "x"
     
      local rv = mtev.mtev_b64_encode(str, string.len(str), buf, 1600)
      assert.is_true(rv > 0)
      local rv = mtev.mtev_b64_decode(buf, rv, buf2, 1001)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

  it("encode to short buffer", function()
    local str = "This is a string"
    local buf_too_small = charstar(10)
    local rv = mtev.mtev_b64_encode(str, string.len(str), buf_too_small, 10)
    assert.is_true(rv == 0)
  end)

  it("decode to short buffer", function()
    local str = "VGhpcyBpcyBhIHN0cmluZw=="
    local buf = charstar(str)
    local buf_too_small = charstar(20)
    local rv = mtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 15)
    assert.is_true(rv == 0)
    local rv = mtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 16)
    assert.are.equal(rv, 16)
  end)
end)
