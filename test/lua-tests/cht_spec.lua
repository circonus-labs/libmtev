ffi.cdef([=[
typedef void mtev_cht_t;

typedef struct {
  char *name;
  void *userdata;
  void (*userdata_freefunc)(void *);
  double owned;
} mtev_cht_node_t;

mtev_cht_t *mtev_cht_alloc();
mtev_cht_t *mtev_cht_alloc_custom(uint16_t weight, uint8_t nbits);
void mtev_cht_free(mtev_cht_t *);
int mtev_cht_set_nodes(mtev_cht_t *, int node_cnt, mtev_cht_node_t *nodes);
int mtev_cht_lookup(mtev_cht_t *, const char *key, mtev_cht_node_t **node);
int mtev_cht_vlookup(mtev_cht_t *, const void *key, size_t keylen, mtev_cht_node_t **node);
int mtev_cht_lookup_n(mtev_cht_t *, const char *key, int w, mtev_cht_node_t **node);
int mtev_cht_vlookup_n(mtev_cht_t *, const void *key, size_t keylen, int w, mtev_cht_node_t **nodes);
]=])

local function mknodes(names)
  local Cnodes = ffi.C.malloc(ffi.sizeof("mtev_cht_node_t[?]", #names))
  ffi.fill(Cnodes, ffi.sizeof("mtev_cht_node_t[?]", #names))
  Cnodes = ffi.cast("mtev_cht_node_t *", Cnodes)
  local Ci = 0

  for i, name in ipairs(names) do 
    Cnodes[Ci].name = ffi.C.strdup(charstar(name))
    Ci = Ci + 1
  end

  return Cnodes
end

local function test_ring_builds(cht, cnt, rsize)
  local node_names = {}
  for i = 1,cnt do table.insert(node_names, "node" .. i) end
  local nodes = mknodes(node_names)
  local rcnt = libmtev.mtev_cht_set_nodes(cht, #node_names, nodes)
  assert.is.equal(rcnt, #node_names)
  local expect = 1.0 / #node_names
  local mdev, total = 0, 0
  for i = 0, #node_names-1 do
    total = total + nodes[i].owned
    mdev = math.max(mdev, math.abs(expect - nodes[i].owned))
    --print(ffi.string(nodes[i].name), nodes[i].owned)
  end
  assert.is_true(mdev < (1/cnt))
  assert.is.equal(total,1)
end

local function run_scenario(cht, input, cnt)
  local node = ffi.new("mtev_cht_node_t *[?]", 1)
  test_ring_builds(cht, cnt, rsize)
  local bcnt, out = {}, {}
  for key,v in pairs(input) do
    assert.is.equal(1, libmtev.mtev_cht_lookup(cht, charstar(key), node))
    local name = ffi.string(node[0][0].name)
    out[key] = name
    bcnt[name] = (bcnt[name] or 0) + 1
  end
  return out, bcnt
end

describe("cht", function()
  local rsize = 1024
  local cht = libmtev.mtev_cht_alloc_custom(32, 20)

  for node_cnt = 1,20 do
    it("should balance relatively well: nodes=" .. node_cnt, function()
      test_ring_builds(cht,node_cnt,rsize)
    end)
  end

  local scenario = {}
  for i = 1,1000 do scenario["shart"..i] = true end

  it("should control redistribution when growing", function()
    local scenario8, bcnt = run_scenario(cht, scenario, 8)
    local scenario9, bcnt = run_scenario(cht, scenario, 9)
    for key,v in pairs(scenario) do
      assert.is_true(scenario8[key] == scenario9[key] or scenario9[key] == "node9")
    end
  end)

  it("should control redistribution when shrinking", function()
    local scenario8, bcnt = run_scenario(cht, scenario, 8)
    local scenario7, bcnt = run_scenario(cht, scenario, 7)
    for key,v in pairs(scenario) do
      assert.is_true(scenario8[key] == scenario7[key] or scenario8[key] == "node8")
    end
  end)

end)
