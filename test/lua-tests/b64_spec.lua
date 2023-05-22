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
    for i=1,10 do
      io.write("i:", i, "\n")
      str = str .. "x"

      local str_len = string.len(str)
      local max_encode_len = libmtev.mtev_b64_encode_len(str_len)
      local actual_encode_len = libmtev.mtev_b64_encode(str, string.len(str), buf, max_encode_len)
      assert.is_true(actual_encode_len > 0)
      assert.is_true(actual_encode_len <= max_encode_len)

      io.write("actual_encode_len:", tostring(actual_encode_len), "\n")
      local max_decode_len = libmtev.mtev_b64_max_decode_len(actual_encode_len)
      io.write("predicted max_decode_len:", tostring(max_decode_len), "\n")
      assert.is_true(str_len <= max_decode_len)
      local actual_decode_len = libmtev.mtev_b64_decode(buf, actual_encode_len, buf2, max_decode_len)
      io.write("actual_decode_len:", tostring(actual_decode_len), "\n")
      io.write("predicted decode - actual = ", tostring(max_decode_len - actual_decode_len), "\n")
      assert.is.equal(actual_decode_len, i)
      assert.is.equal(str, ffi.string(buf2, actual_decode_len))
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
    local encoded_str = "VGhpcyBpcyBhIHN0cmluZw=="
    local decoded_str = "This is a string"
    local buf = charstar(encoded_str)
    local decode_len = tonumber(libmtev.mtev_b64_max_decode_len(string.len(encoded_str)))
    local buf_too_small = charstar(decode_len)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 3)
    assert.is.equal(0, rv)
    assert.is_false(ffi.string(buf_too_small) == decoded_str)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 2)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small) == decoded_str)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 1)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small) == decoded_str)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small) == decoded_str)
  end)

  it("decode to short buffer (=)", function()
    local encoded_str = "VGhpcyBpcyBhIHN0cmluZy4="
    local decoded_str = "This is a string."
    local buf = charstar(encoded_str)
    local decode_len = tonumber(libmtev.mtev_b64_max_decode_len(string.len(encoded_str)))
    local buf_too_small = charstar(decode_len)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 2)
    assert.is.equal(0, rv)
    assert.is_false(ffi.string(buf_too_small) == decoded_str)
    rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 1)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small) == decoded_str)
    rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small) == decoded_str)
  end)

  it("decode to short buffer (full)", function()
    local encoded_str = "VGhpcyBpcyBhIHN0cmluZy4u"
    local decoded_str = "This is a string.."
    local buf = charstar(encoded_str)
    local decode_len = tonumber(libmtev.mtev_b64_max_decode_len(string.len(encoded_str)))
    local buf_too_small = charstar(decode_len)
    local rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len - 1)
    assert.is.equal(0, rv)
    assert.is_false(ffi.string(buf_too_small) == decoded_str)
    rv = libmtev.mtev_b64_decode(buf, string.len(encoded_str), buf_too_small, decode_len)
    assert.is.equal(string.len(decoded_str), rv)
    assert.is_true(ffi.string(buf_too_small, decode_len) == decoded_str)
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
      assert.is_true(encodelen_actual <= encodelen_expected)
      local decodelen_expected = libmtev.mtev_b64_max_decode_len(encodelen_actual)
      local decodebuf = charstar(tonumber(decodelen_expected))
      local decodelen = libmtev.mtev_b64_decode(encodebuf, encodelen_actual, decodebuf, decodelen_expected)
      assert.is.equal(string.len(input_str), tonumber(decodelen))
      assert.is.equal(input_str, ffi.string(decodebuf, decodelen))
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
