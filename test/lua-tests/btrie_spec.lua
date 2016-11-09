ffi.cdef([=[
struct in_addr { char _inside[4]; };
struct in6_addr { char _inside[16]; };
int inet_pton(int af, const char * restrict src, void * restrict dst);

typedef struct btrie_collapsed_node *btrie;
void mtev_drop_tree(btrie *, void (*)(void *));
void mtev_add_route(btrie *, uint32_t *, unsigned char, void *);
void mtev_add_route_ipv4(btrie *, struct in_addr *, unsigned char, void *);
void mtev_add_route_ipv6(btrie *, struct in6_addr *, unsigned char, void *);
int mtev_del_route_ipv4(btrie *, struct in_addr *, unsigned char, void (*)(void *));
int mtev_del_route_ipv6(btrie *, struct in6_addr *, unsigned char, void (*)(void *));
void *mtev_find_bpm_route_ipv4(btrie *tree, struct in_addr *a, unsigned char *);
void *mtev_find_bpm_route_ipv6(btrie *tree, struct in6_addr *a, unsigned char *);
]=])

-- This is for Illumos where inet_pton comes from libnsl, not libc
local nsl
pcall((function() nsl = ffi.load('nsl') end))
local inet_pton, AF_INET6
local AF_INET = 2
if nsl ~= nil then
  inet_pton = nsl.inet_pton
  AF_INET6 = 26
else
  inet_pton = ffi.C.inet_pton
  AF_INET6 = 30
end

local mkip = (function ()
  local ip4 = ffi.new("struct in_addr[?]", 1)
  local ip6 = ffi.new("struct in6_addr[?]", 1)
  return function(ip)
    if(inet_pton(AF_INET, charstar(ip), ip4) == 1) then return ip4 end
    if(inet_pton(AF_INET6, charstar(ip), ip6) == 1) then return ip6 end
    return nil
  end
end)()

local function add_ip_route(f, b, addr, mask, v)
  local i = addr:find("/")
  if i ~= nil then
    mask = tonumber(addr:sub(i+1))
    addr = addr:sub(1,i-1)
  end
  addr = mkip(addr)
  return f(b, addr, mask, ffi.cast("void *", v))
end

local function add_ip4_route(b, addr, v)
  return add_ip_route(libmtev.mtev_add_route_ipv4, b, addr, 32, v)
end

local function add_ip6_route(b, addr, v)
  return add_ip_route(libmtev.mtev_add_route_ipv6, b, addr, 128, v)
end

local _ip4s = {}
_ip4s['0.0.0.0/0'] = 10
_ip4s['10.0.0.0/8'] = 1918
_ip4s['192.168.0.0/16'] = 1918
_ip4s['199.15.220.0/22'] = 100
_ip4s['199.15.221.0/24'] = 101
_ip4s['199.15.222.0/23'] = 102

local _ip6s = {}
_ip6s['::1/48'] = 127

describe("btrie", function()
  it("should handle ipv4", function()
    local btrie = ffi.new("btrie[?]", 1, ffi.cast("void *", 0))
    local mask_out = ffi.new("unsigned char[?]", 1)
    local function test(addr, v)
      local o = ffi.cast("int", libmtev.mtev_find_bpm_route_ipv4(btrie, mkip(addr), mask_out))
      assert.are.equal(o,v)
    end
    for k,v in pairs(_ip4s) do
      add_ip4_route(btrie, k, v)
    end
    test("1.2.3.4", 10)
    test("10.10.2.1", 1918)
    test("192.168.12.1", 1918)
    test("199.15.219.123", 10)
    test("199.15.220.11", 100)
    test("199.15.221.11", 101)
    test("199.15.222.11", 102)
    test("199.15.223.11", 102)
    libmtev.mtev_drop_tree(btrie, nil)
  end)

  it("should handle ipv6", function()
    local btrie6 = ffi.new("btrie[?]", 1, ffi.cast("void *", 0))
    local mask_out = ffi.new("unsigned char[?]", 1)
    local function test(addr, v)
      local o = ffi.cast("int", libmtev.mtev_find_bpm_route_ipv6(btrie6, mkip(addr), mask_out))
      assert.are.equal(o,v)
    end
    for k,v in pairs(_ip6s) do
      add_ip6_route(btrie6, k, v)
    end
    test("::1", 127)
    libmtev.mtev_drop_tree(btrie6, nil)
  end)
end)
