ffi.cdef([=[
typedef struct mtev_prependable_str_buff{
  char *buff;
  char *string;
  unsigned int buff_len;
} mtev_prependable_str_buff_t;

void mtev_prepend_str(mtev_prependable_str_buff_t *buff, const char* str, unsigned int str_len);
mtev_prependable_str_buff_t * mtev_prepend_str_alloc();
void mtev_prepend_str_free(mtev_prependable_str_buff_t *buff);
int mtev_prepend_strlen(mtev_prependable_str_buff_t *buff);
]=])

describe("alloc_and_free", function()
  it("should alloc and dealloc", function()
    local str = libmtev.mtev_prepend_str_alloc()
    assert.is.equal(str.buff_len, 8, "default buff len")
    assert.is.equal(0, libmtev.mtev_prepend_strlen(str), "empty")
    libmtev.mtev_prepend_str_free(str)
  end)

  it("should store strings", function()
    local str = libmtev.mtev_prepend_str_alloc()
    libmtev.mtev_prepend_str(str, charstar("World"), 5)
    assert.is.equal("World", ffi.string(str.string), "contains world")
    assert.is.equal(str.buff_len, 8, "size")
    libmtev.mtev_prepend_str(str, charstar("Hello "), 6)
    assert.is.equal("Hello World", ffi.string(str.string), "contains hello world")
    assert.is.equal(str.buff_len, 22, "grew")
    libmtev.mtev_prepend_str(str, charstar("!"), 1)
    assert.is.equal("!Hello World", ffi.string(str.string), "contains !hello world")
    assert.is.equal(str.buff_len, 22, "did not grow")
    libmtev.mtev_prepend_str_free(str)
  end)
end)
