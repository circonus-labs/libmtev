ffi.cdef([=[
  struct iovec {
    void *iov_base;
    size_t iov_len;
  };
  int mtev_b64_decode(const char *, size_t, unsigned char *, size_t);
  int mtev_b64_encode(const unsigned char *, size_t, char *, size_t);
  int mtev_b64_encodev(struct iovec *, size_t, char *, size_t);
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
      local encode_len = libmtev.mtev_b64_encode_len(str_len)
      local rv = libmtev.mtev_b64_encode(str, string.len(str), buf, encode_len)
      assert.is_true(rv > 0)
      assert.are.equal(rv, encode_len)

      local decode_len = libmtev.mtev_b64_max_decode_len(encode_len)
      assert.is_true(str_len <= decode_len)
      local rv = libmtev.mtev_b64_decode(buf, rv, buf2, decode_len)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

  it("encode to short buffer", function()
    local str = "This is a string"
    local encode_len = tonumber(libmtev.mtev_b64_encode_len(string.len(str)))
    local buf_too_small = charstar(encode_len)
    local rv = libmtev.mtev_b64_encode(str, string.len(str), buf_too_small, encode_len-1)
    assert.is.equal(0, rv)
  end)

  it("decode to short buffer (==)", function()
    local str = "VGhpcyBpcyBhIHN0cmluZw=="
    local buf = charstar(str)
    local decode_len = tonumber(libmtev.mtev_b64_max_decode_len(string.len(str)))
    assert.are.equal(decode_len,18)
    local buf_too_small = charstar(decode_len)
    local rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 15)
    assert.is.equal(0, rv)
    local rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 16)
    assert.are.equal(16, rv)
  end)

  it("decode to short buffer (=)", function()
    local str = "VGhpcyBpcyBhIHN0cmluZwa="
    local buf = charstar(str)
    local buf_too_small = charstar(17)
    local rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 16)
    assert.is.equal(0, rv)
    rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 17)
    assert.are.equal(17, rv)
  end)

  it("decode to short buffer (full)", function()
    local str = "VGhpcyBpcyBhIHN0cmluZwaa"
    local buf = charstar(str)
    local buf_too_small = charstar(18)
    local rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 17)
    assert.is.equal(0, rv)
    rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 18)
    assert.are.equal(18, rv)
  end)

  it("decode to short buffer (invalid)", function()
    local str = "VGhpcyBpcyBhIHN0cmluZw=a"
    local buf = charstar(str)
    local buf_too_small = charstar(17)
    local rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 15)
    assert.are.equal(0, rv)
    rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 16)
    assert.are.equal(16, rv)
    rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 17)
    assert.are.equal(16, rv)
    rv = libmtev.mtev_b64_decode(buf, string.len(str), buf_too_small, 18)
    assert.are.equal(16, rv)
  end)

  it("encodev decodes correctly", function()
    local roundtrip = function(strs)
      local iovs = ffi.new("struct iovec[?]", #strs)
      local total_len = 0
      local input_str = ""
      for idx=1,#strs do
        iovs[idx-1].iov_base = charstar(strs[idx])
        iovs[idx-1].iov_len = string.len(strs[idx])
        input_str = input_str .. strs[idx]
      end
      local encodelen_expected = libmtev.mtev_b64_encode_len(string.len(input_str))
      local encodebuf = charstar(tonumber(encodelen_expected))
      local encodelen_actual = libmtev.mtev_b64_encodev(iovs, #strs, encodebuf, encodelen_expected)
      assert.are.equal(encodelen_expected, encodelen_actual)
      local decodebuf = charstar(tonumber(encodelen_actual))
      local decodelen = libmtev.mtev_b64_decode(encodebuf, encodelen_actual, decodebuf, encodelen_actual)
      assert.are.equal(tonumber(decodelen), string.len(input_str))
      assert.are.equal(ffi.string(decodebuf, decodelen), input_str)
    end

    local str_loop1 = ""
    local str_loop2
    local str_loop3
    for loop1=0,4 do
      roundtrip({str_loop1})
      str_loop2 = ""
      for loop2=0,4 do
        roundtrip({str_loop1, str_loop2})
        str_loop3 = ""
        for loop3=0,4 do
          roundtrip({str_loop1, str_loop2, str_loop3})
          str_loop3 = str_loop3 .. tostring(loop3)
        end
        str_loop2 = str_loop2 .. tostring(loop2)
      end
      str_loop1 = str_loop1 .. tostring(loop1)
    end
  end)
end)
