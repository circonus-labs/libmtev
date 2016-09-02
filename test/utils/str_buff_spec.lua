ffi.cdef([=[
typedef struct mtev_str_buff{
  char *string;
  char *end;
  uint buff_len;
} mtev_str_buff_t;

mtev_str_buff_t * mtev_str_buff_alloc();
mtev_str_buff_t * mtev_str_buff_alloc_sized();
void mtev_append_str_buff(mtev_str_buff_t *buff, const char* str, uint str_len);
void mtev_str_buff_free(mtev_str_buff_t *buff);
int mtev_str_buff_len(mtev_str_buff_t *buff);
]=])

describe("alloc_and_free", function()
  it("should alloc and dealloc", function()
    local str = mtev.mtev_str_alloc()
    assert.is.equal(str.buff_len, 8, "default buff len")
    assert.is.equal(0, mtev.mtev_strlen(str), "empty")
    mtev.mtev_str_free(str)
  end)

  it("should store strings", function()
    local str = mtev.mtev_str_alloc()
    mtev.mtev_append_str(str, charstar("Hello "), 6)
    assert.is.equal("Hello ", ffi.string(str.string), "contains hello")
    assert.is.equal(str.buff_len, 8, "size")
    mtev.mtev_append_str(str, charstar("World"), 5)
    assert.is.equal("Hello World", ffi.string(str.string), "contains hello world")
    assert.is.equal(str.buff_len, 22, "grew")
    mtev.mtev_append_str(str, charstar("!"), 1)
    assert.is.equal("Hello World!", ffi.string(str.string), "contains hello world!")
    assert.is.equal(str.buff_len, 22, "did not grow")
    mtev.mtev_str_free(str)
  end)

  it("should dealloc when cast to string", function()
    local str_buff_ptr = ffi.new("mtev_str_buff_t[?]", 1)
    local str_buff = mtev.mtev_str_alloc()
    str_buff_ptr[1] = str_buff
    mtev.mtev_append_str(str_buff, charstar("Hello World!"), 6)
    assert.is.equal("Hello World!", ffi.string(str_buff.string), "buff contains hello world!")
    assert.is.equal(str_buff, str_buff_ptr[1], "freed the buffer")
    local str = mtev.mtev_str_buff_to_string(str_buff) 
    assert.is.equal(nil, str_buff_ptr[1], "freed the buffer")
    assert.is.equal("Hello World!", ffi.string(str), "extracted string contains hello world!")
    mtev.free(str)
  end)
end)
