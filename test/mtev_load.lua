ffi = require('ffi')
ffi.cdef([=[
  int mtev_b64_decode(const char *, size_t, unsigned char *, size_t);
  int mtev_b64_encode(const unsigned char *, size_t, char *, size_t);
  int mtev_b32_decode(const char *, size_t, unsigned char *, size_t);
  int mtev_b32_encode(const unsigned char *, size_t, char *, size_t);
]=])
mtev = ffi.load('mtev')

function charstar(str)
  if type(str) == 'number' then
    return ffi.new("char[?]", str, 0)
  end
  local len = string.len(str)
  local buf = ffi.new("char[?]", len+1, 0)
  ffi.copy(buf, str, len)
  return buf
end
