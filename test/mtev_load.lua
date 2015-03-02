ffi = require('ffi')
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
