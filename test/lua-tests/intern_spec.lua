io = require('io')
ffi.cdef([=[
  typedef struct { uintptr_t opaque1; } mtev_intern_t;
  typedef struct mtev_intern_pool mtev_intern_pool_t;
  typedef struct {
    uint32_t item_count;
    uint32_t extent_count;
    size_t allocated;
    size_t internal_memory;
    size_t available_total;
    size_t available[32];
    uint32_t fragments_total;
    uint32_t fragments[32];
    uint32_t staged_count;
    size_t staged_size;
  } mtev_intern_pool_stats_t;
  mtev_intern_t mtev_intern(const void *, size_t);
  mtev_intern_t mtev_intern_str(const char *, size_t);
  const char *mtev_intern_get_str(mtev_intern_t);
  void mtev_intern_release(mtev_intern_t);
  void mtev_intern_remove(mtev_intern_t);
  int mtev_intern_pool_item_count(mtev_intern_pool_t *);
  int mtev_intern_pool_compact(mtev_intern_pool_t *, bool);
  void mtev_intern_pool_stats(mtev_intern_pool_t *, mtev_intern_pool_stats_t *);
]=])

-- 100k repeatably unique "words"
  local words = function()
    local i = 100000
    math.randomseed(1)
    return function ()
      i = i - 1
      if i < 0 then return nil end
      return mtev.sha256_hex(math.random())
    end
  end

describe("intern strings", function()
  local default_pool = ffi.cast("mtev_intern_pool_t *", 0)
  local f,g,h
  local cnt = 0
  local start_frags, compaction_count
  it("same strings have same value", function()
    f = libmtev.mtev_intern_str("this", 0)
    g = libmtev.mtev_intern_str("this", 0)
    assert.is_equal(f.opaque1, g.opaque1)
  end)
  it("different string has different value",function()
    h = libmtev.mtev_intern_str("something else", 0)
    assert.is_not_equal(f.opaque1, h.opaque1)
  end)
  it("releases", function()
    libmtev.mtev_intern_remove(f)
    libmtev.mtev_intern_release(f)
    libmtev.mtev_intern_release(g)
    libmtev.mtev_intern_remove(h)
    libmtev.mtev_intern_release(h)
  end)
  it("new copy has different value", function()
    -- "that" is the same size as "this"
    local that = libmtev.mtev_intern_str("that", 0)
    local this = libmtev.mtev_intern_str("this", 0)
    assert.is_not_equal(this, f)
    libmtev.mtev_intern_remove(that)
    libmtev.mtev_intern_release(that)
    libmtev.mtev_intern_remove(this)
    libmtev.mtev_intern_release(this)
  end)
  it("loads/unloads", function()
    for v in words() do
      local f = libmtev.mtev_intern_str(v, 0)
      libmtev.mtev_intern_release(f)
    end
  end)
  it("loads/unloads in batch", function()
    local m = {}
    local cnt = 0
    for v in words() do
      m[v] = libmtev.mtev_intern_str(v, 0)
      cnt = cnt + 1
      if cnt > 2000 then
        for k in pairs(m) do
          libmtev.mtev_intern_remove(m[k])
          libmtev.mtev_intern_release(m[k])
          m[k] = nil
          cnt = cnt - 1
          if cnt < 1000 then break end
        end
      end
    end
    for k in pairs(m) do
      libmtev.mtev_intern_remove(m[k])
      libmtev.mtev_intern_release(m[k])
    end
  end)
  it("loads the dictionary 2x", function()
    for i = 1,2 do
      for v in words() do 
        libmtev.mtev_intern_str(v, 0)
        if i == 1 then cnt = cnt + 1 end
      end
    end
  end)
  it("has the right key count", function()
    assert.is_equal(cnt, libmtev.mtev_intern_pool_item_count(default_pool))
  end)
  it("has stats", function()
    local stats = ffi.new("mtev_intern_pool_stats_t[1]")
    libmtev.mtev_intern_pool_stats(default_pool, stats)
    assert.is_not_equal(stats[0].allocated, stats[0].available_total)
  end)
  it("loads the dictionary again (dropping)", function()
    for v in words() do 
      local f = libmtev.mtev_intern_str(v, 0)
      libmtev.mtev_intern_remove(f)
      -- release for the two prior loads and this one
      for i = 1,3 do libmtev.mtev_intern_release(f) end
    end
  end)
  it("has the right key count", function()
    assert.is_equal(0, libmtev.mtev_intern_pool_item_count(default_pool))
    local stats = ffi.new("mtev_intern_pool_stats_t[1]")
    libmtev.mtev_intern_pool_stats(default_pool, stats)
    assert.is_equal(0, stats[0].item_count)
    start_frags = stats[0].fragments_total
  end)
  it("compacts", function()
    compaction_count = libmtev.mtev_intern_pool_compact(default_pool, true)
    assert.is_not_equal(-1, compaction_count)
  end)
  it("has consolidated freelist", function()
    local stats = ffi.new("mtev_intern_pool_stats_t[1]")
    libmtev.mtev_intern_pool_stats(default_pool, stats)
    assert.is_equal(stats[0].allocated, stats[0].available_total)
    for i = 0,31 do
      assert.is_true(stats[0].available_total == stats[0].available[i] or
                     0 == stats[0].available[i])
    end
    assert.is_true(stats[0].fragments_total <= stats[0].extent_count)
    assert.is_equal(stats[0].fragments_total, start_frags - compaction_count)
  end)
end)
