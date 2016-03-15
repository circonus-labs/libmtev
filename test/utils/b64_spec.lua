ffi.cdef([=[
  int mtev_b64_decode(const char *, size_t, unsigned char *, size_t);
  int mtev_b64_encode(const unsigned char *, size_t, char *, size_t);
  size_t mtev_b64_encode_len(size_t);
  size_t mtev_b64_max_decode_len(size_t);
]=])

describe("mtev_b64", function()
  it("A == decode(encode(A))", function()
    local str = ""
    local buf = charstar(1600)
    local buf2 = charstar(1001)
    for i=1,1000 do
      str = str .. "x"

      local str_len = string.len(str)
      local encode_len = mtev.mtev_b64_encode_len(str_len)
      local rv = mtev.mtev_b64_encode(str, string.len(str), buf, encode_len)
      assert.is_true(rv > 0)
      assert.are.equal(rv, encode_len)

      local decode_len = mtev.mtev_b64_max_decode_len(encode_len)
      assert.is_true(str_len <= decode_len)
      local rv = mtev.mtev_b64_decode(buf, rv, buf2, decode_len)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

  it("encode to short buffer", function()
    local str = "This is a string"
    local encode_len = tonumber(mtev.mtev_b64_encode_len(string.len(str)))
    local buf_too_small = charstar(encode_len)
    local rv = mtev.mtev_b64_encode(str, string.len(str), buf_too_small, encode_len-1)
    assert.is_true(rv == 0)
  end)

  it("decode to short buffer", function()
    local str = "VGhpcyBpcyBhIHN0cmluZw=="
    local buf = charstar(str)
    local decode_len = tonumber(mtev.mtev_b64_max_decode_len(string.len(str)))
    assert.are.equal(decode_len,18)
    local buf_too_small = charstar(decode_len)
    local rv = mtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 15)
    assert.is_true(rv == 0)
    local rv = mtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 16)
    assert.are.equal(rv, 16)
  end)
end)
