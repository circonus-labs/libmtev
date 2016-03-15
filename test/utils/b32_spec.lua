ffi.cdef([=[
  int mtev_b32_decode(const char *, size_t, unsigned char *, size_t);
  int mtev_b32_encode(const unsigned char *, size_t, char *, size_t);
  size_t mtev_b32_max_decode_len(size_t);
  size_t mtev_b32_encode_len(size_t);
]=])

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

      local str_len = string.len(str)
      local encode_len = mtev.mtev_b32_encode_len(str_len)
      local rv = mtev.mtev_b32_encode(str, str_len, buf, encode_len)
      assert.is_true(rv > 0 and rv <= 1608)
      assert.are.equal(rv, encode_len)

      local decode_len = mtev.mtev_b32_max_decode_len(encode_len)
      assert.is_true(str_len <= decode_len)
      local rv = mtev.mtev_b32_decode(buf, rv, buf2, decode_len)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

  it("encode to short buffer", function()
    local str = "This is a string"
    local encode_len = tonumber(mtev.mtev_b32_encode_len(string.len(str)))
    local buf_too_small = charstar(encode_len)
    local rv = mtev.mtev_b32_encode(str, string.len(str), buf_too_small, encode_len-1)
    assert.is_true(rv == 0)
  end)

  it("decode to short buffer", function()
    local str = "KRUGS4ZANFZSAYJAON2HE2LOM4======"
    local buf = charstar(str)
    local decode_len = tonumber(mtev.mtev_b32_max_decode_len(string.len(str)))
    assert.are.equal(decode_len, 20)
    local buf_too_small = charstar(decode_len)
    local rv = mtev.mtev_b32_decode(buf, string.len(str), buf_too_small, decode_len - 1)
    assert.is_true(rv == 0)
    local rv = mtev.mtev_b32_decode(buf, string.len(str), buf_too_small, decode_len)
    assert.are.equal(rv, 16)
  end)
end)
