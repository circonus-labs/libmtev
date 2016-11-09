ffi.cdef([=[
  typedef struct { char opaque[64]; } mtev_perftimer_t;
  void mtev_perftimer_start(mtev_perftimer_t *);
  int64_t mtev_perftimer_elapsed(mtev_perftimer_t *);
  void usleep(unsigned long us);
]=])

describe("mtev_perftimer", function()

  it("should load ffi", function()
    assert.truthy(libmtev ~= nil)
  end)

  it("time a 100ms sleep", function(c)
    local perftimer = ffi.new("mtev_perftimer_t[?]", 1)
    libmtev.mtev_perftimer_start(perftimer)
    ffi.C.usleep(100000)
    local ns = libmtev.mtev_perftimer_elapsed(perftimer)
    assert.truthy(ns > 100000000)
    assert.truthy(ns < 110000000)
  end)

end)
