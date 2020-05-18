--
-- This ptrace module attaches a global annotation with all active http requests at the time of the
-- crash, extracted from the http_observer-module.
--
-- ptrace needs to be invoked with the following parameters for this module to work:
--
--   --load=$path_to_http_observer_so_file --global lookup
--
-- E.g.
--
--    /opt/backtrace/bin/ptrace \
--     --config=/opt/noit/prod/etc/ptrace.conf \
--     --kv=hostcn:$HOSTCN,location:$LOCATION,provider:$PROVIDER,environment:$ENVIRONMENT,trace_reason:$REASON \
--     --kv=branch:$NOIT_BRANCH,version:$NOIT_VERSION,version_tstamp:$NOIT_VERSION_TSTAMP,buildmachine:$BUILD_NOIT_UNAME_N \
--     --modules-path=/opt/circonus/share/ptrace/ \
--     --load=/opt/circonus/libexec/mtev/http_observer.so --global lookup \
--     $PID
--
local LIMIT_MEMBER_COUNT = 128

local function L(...)
  pmodule.log(pmodule.log_level.error, string.format(...))
end

local function bt2add(bt_var)
  return pmodule.variable_from_bt(bt_var):address()
end

local function poke(addr, len)
  return pmodule.address_read_raw(addr, len)
end

local function str2num(str)
  local x = 0
  local n = string.len(str)
  for i=1,n do
    x = 256 * x + string.byte(str, n-i+1)
  end
  return x
end

local function poke_num(addr, len)
  return str2num(poke(addr, len))
end

local function poke_str(addr, len)
  return pmodule.address_read_string(addr, len or 256)
end

local function poke_ptr_arr(addr, len)
  local out = {}
  local str = pmodule.address_read_raw(addr, 8 * len)
  for i=1,len do
    out[i] = str2num(str:sub( 8*(i-1) + 1, 8*i ))
  end
  return out
end

local function deref(addr)
  return poke_num(addr, 8)
end

local function val2json(v, rec)
  rec = rec or 0
  if rec > 3 then
    return '"<recursion limit reached>"'
  end
  local tpe = type(v)
  if tpe == "string" then
    return '"' .. v:gsub('"','\\"') .. '"'
  elseif tpe == "table" then
    local buf = {}
    for key,val in pairs(v) do
      -- we only support string keys
      buf[#buf+1] = string.format([[ "%s" : %s ]], key, val2json(val))
    end
    return '{' .. table.concat(buf, ",") .. '}'
  else
    return tostring(v)
  end
end

--
-- We have to do some manual pointer arithmetic to pick out the http request information from the
-- lookup hash table. Here are the relevant structs, with manually computed offset at the time of
-- writing.
--
--                                          OFFSET
-- struct ck_hs_map {                       --------
-- 	unsigned int generation[CK_HS_G];
--  unsigned int probe_maximum;
--  unsigned long mask;
--  unsigned long step;
--  unsigned int probe_limit;
--  unsigned int tombstones;
--  unsigned long n_entries;                  40
--  unsigned long capacity;                   48
--  unsigned long size;                       56
--  CK_HS_WORD *probe_bound;
--  const void **entries;                     72
-- };
--
-- typedef struct ck_hash_attr {
--   void *data;                              -16
--   void *key_ptr;                           -8
--   ck_key_t key;                            0    <-- We have a pointer to this entry
-- } ck_hash_attr_t;
--
-- typedef struct {
--   mtev_http_session_ctx *ctx;              0
--   uint64_t id;
--   uint64_t request_start_ns;
--   uint64_t request_complete_ns;
--   uint64_t read_start_ns;
--   uint64_t read_complete_ns;
--   uint64_t response_start_ns;
--   uint64_t response_complete_ns;
--   uint64_t inbytes;
--   uint64_t outbytes;
--   mtev_hash_table info;                     128
-- } http_entry_t;
--
local function walk_hash(a_hash)
  local a_map = deref(a_hash + 8) -- deref( hash.u.hs.map ) points to ck_hs_map
  return coroutine.wrap(function()
      if (a_map > 0) then
        local cap = poke_num(a_map+48, 4) -- .capacity
        local entr_p = poke_num(a_map+72, 8) -- .entries
        local entr_l = poke_ptr_arr(entr_p, cap) -- list of pointers to entries
        local cnt = 0
        for i, a_ent in ipairs(entr_l) do
          -- a_ent points to ck_hash_attr_t
          if a_ent > 0 then
            cnt = cnt + 1
            if cnt > LIMIT_MEMBER_COUNT then break end
            local a_key  = a_ent - 8;  -- .key_ptr
            local a_data = a_ent - 16  -- .data
            coroutine.yield(a_key, a_data)
          end
        end
      end
  end)
end

-- taken from mtev-hash-module
local function parse_lookup(bt_var)
  local out = {}
  local cnt = 0
  local a_hash = bt2add(bt_var)
  for a_key, a_data in walk_hash(a_hash) do
    -- a_data poionts to http_entry_t
    local a_info = deref(a_data) + 128 -- .info
    local ent = {}
    for b_key, b_data in walk_hash(a_info) do
      local key = poke_str(deref(b_key), 100)
      local data = poke_str(deref(b_data), 100)
      ent[key] = data
    end
    out[string.format("[%d] %s", cnt, ent.uri or "-")] = ent
    cnt = cnt + 1
  end
  return out
end

local function postattach_cb()
  local bt = pmodule.backtrace();
  for var, obj, cu in bt:variables(), {name = "lookup"} do
    local bt_var = pmodule.bt_query("lookup", obj, cu)
    local json = val2json(parse_lookup(bt_var))
    bt:annotate(pmodule.annotation.json, string.format('{ "json" :  { "http_observer" : %s } }', json))
  end
end

local function pm_load()
  L("module mtev-http-observer: load")
  pmodule.register(pmodule.event.postattach, postattach_cb)
end

pmodule.define {
  id = "mtev-http-observer",
  load = pm_load,
}
