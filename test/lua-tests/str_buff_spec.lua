ffi.cdef([=[
typedef struct mtev_str_buff{
  char *string;
  char *end;
  uint32_t buff_len;
} mtev_str_buff_t;

mtev_str_buff_t * mtev_str_buff_alloc();
mtev_str_buff_t * mtev_str_buff_alloc_sized();
void mtev_append_str_buff(mtev_str_buff_t *buff, const char* str, uint32_t str_len);
void mtev_str_buff_free(mtev_str_buff_t *buff);
int mtev_str_buff_len(mtev_str_buff_t *buff);
char* mtev_str_buff_to_string(mtev_str_buff_t **buff);
]=])

describe("alloc_and_free", function()
  it("should alloc and dealloc", function()
    local str = libmtev.mtev_str_buff_alloc()
    assert.is.equal(str.buff_len, 8, "default buff len")
    assert.is.equal(0, libmtev.mtev_str_buff_len(str), "empty")
    libmtev.mtev_str_buff_free(str)
  end)

  it("should store strings", function()
    local str = libmtev.mtev_str_buff_alloc()
    libmtev.mtev_append_str_buff(str, charstar("Hello "), 6)
    assert.is.equal("Hello ", ffi.string(str.string), "contains hello")
    local start_size = str.buff_len
    libmtev.mtev_append_str_buff(str, charstar("World"), 5)
    assert.is.equal("Hello World", ffi.string(str.string), "contains hello world")
    local grow_size = str.buff_len
    assert.is_true(grow_size > start_size, "grew")
    libmtev.mtev_append_str_buff(str, charstar("!"), 1)
    assert.is.equal("Hello World!", ffi.string(str.string), "contains hello world!")
    assert.is.equal(str.buff_len, grow_size, "did not grow")
    libmtev.mtev_str_buff_free(str)
  end)

  it("should dealloc when cast to string", function()
    local str_buff = libmtev.mtev_str_buff_alloc()
    local str_buff_ptr = ffi.new("mtev_str_buff_t *[?]", 1)
    str_buff_ptr[0] = str_buff
    libmtev.mtev_append_str_buff(str_buff, charstar("Hello World!"), 12)
    assert.is.equal("Hello World!", ffi.string(str_buff.string), "buff contains hello world!")
    local str = libmtev.mtev_str_buff_to_string(str_buff_ptr) 
    assert.is.equal(nil, str_buff_ptr[0], "freed the buffer")
    assert.is.equal("Hello World!", ffi.string(str), "extracted string contains hello world!")
  end)
end)
