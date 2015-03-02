describe("mtev_b32", function()
  local ffi = require('ffi')
  ffi.cdef([=[
    int mtev_b32_decode(const char *, size_t, unsigned char *, size_t);
    int mtev_b32_encode(const unsigned char *, size_t, char *, size_t);
  ]=])
  local mtev = ffi.load("mtev")

  it("should load ffi", function()
    assert.truthy(mtev ~= nil)
  end)

  local function charstar(str)
    if type(str) == 'number' then
      return ffi.new("char[?]", str, 0)
    end
    local len = string.len(str)
    local buf = ffi.new("char[?]", len+1, 0)
    ffi.copy(buf, str, len)
    return buf
  end

  it("A == decode(encode(A))", function()
    local str = ""
    local buf = charstar(1600)
    local buf2 = charstar(1001)
    for i=1,1000 do
      str = str .. "x"
     
      local rv = mtev.mtev_b32_encode(str, string.len(str), buf, 1600)
      assert.is_true(rv > 0)
      local rv = mtev.mtev_b32_decode(buf, rv, buf2, 1001)
      assert.are.equal(rv, i)
      assert.are.equal(str, ffi.string(buf2, rv))
    end
  end)

end)
