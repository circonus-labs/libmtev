ffi = require('ffi')
ffi.cdef([=[
void *malloc(size_t);
char *strdup(const char *);
void free(void *);
char *strsignal(int sig);
]=])
libmtev = ffi.load('mtev')

function charstar(str)
  if type(str) == 'number' then
    if str < 1 then
      str = 1
    end
    return ffi.new("char[?]", str, 0)
  end
  local len = string.len(str)
  local buf = ffi.new("char[?]", len+1, 0)
  ffi.copy(buf, str, len)
  return buf
end

function strsignal(sig)
  return ffi.string(ffi.C.strsignal(sig))
end
