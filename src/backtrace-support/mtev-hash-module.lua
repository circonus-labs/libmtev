local LIMIT_MEMBER_COUNT = 128

--
-- Helper
--

local function L(...)
  pmodule.log(pmodule.log_level.info, string.format(...))
end

local function bt2str(bt_var)
  local addr = pmodule.variable_from_bt(bt_var):value()
  return pmodule.address_read_string(addr, 256)
end

local function bt2val(bt_var)
  return pmodule.variable_from_bt(bt_var):value()
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

-- convert byte string to hex-string
local function bytes2str(bytes)
  buf = {}
  for i=1,bytes:len() do
    buf[#buf+1] = string.format("%0.2x", bytes:byte(i))
    if i % 8 == 0 then
      buf[#buf+1] = " . "
    elseif i % 4 == 0 then
      buf[#buf+1] = " "
    else
      buf[#buf+1] = ""
    end
  end
  return table.concat(buf, "")
end

-- Infer value type.
local function poke_val(addr, max_len, inf_len, rec)
  max_len = max_len or 128
  inf_len = inf_len or 16
  rec = rec or 0
  if rec >= 2 then
    return string.format("0x%x", addr)
  end
  local inf = pmodule.address_read_raw(addr, inf_len)
  local is_ascii = true
  for i=1, inf_len do
    local c = inf:byte(i)
    if c == 0 then
      break
    end
    if not( 32 <= c and c  <= 126 ) then -- ASCII CHARS
      is_ascii = false
      break
    end
  end
  local is_addr = false
  local addr_val = str2num(inf:sub(1, 8))
  if 0x700000000000 <= addr_val and addr_val <= 0xFFFFFFFFFFFF then
    is_addr = true
  end
  local num_val = str2num(inf:sub(1, 8))
  local is_small_num = num_val < 100
  if is_ascii then
    return pmodule.address_read_string(addr, max_len)
  elseif is_addr then
    return "->" .. poke_val(addr_val, max_len, inf_len, rec + 1)
  elseif is_small_num then
    return tostring(num_val)
  else
    return bytes2str(inf)
  end
end

local function print_mem(addr, len)
  local str = bytes2str(poke(addr, len))
  L("XXX MEM[0x%x]: \n%s", addr, str)
end

local function mkvar(name, val, owner)
  local pt_var = pmodule.create_variable("<type>", name, 0, 0, owner)
  pt_var:set_string(tostring(val))
  local fr = owner:frame()
  if fr then -- global variables don't have frames
    fr:add_variable(pt_var)
  end
  return pt_var
end

--
-- We don't have symbols for ck_hs, so we need to do some pointer arithmetic.  One reason for this
-- is, that we build libck.so without DRWARF symbols.  But even with DWARF, the map entry shows up
-- as a void* in backtrace.  According to Sammy Bahra this is because of "lazy loading of types" and
-- "[..] the type info for that CU is incomplete its just a forward declaration."  While I don't
-- understand this in full, doing the pointer arithmetic is straight-forward enough for us to get
-- along without symbol support.
--
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
--  };
--
-- typedef struct ck_hash_attr {
--   void *data;                              -16
--   void *key_ptr;                           -8
--   ck_key_t key;                            0 <-- We have a pointer to this entry
-- } ck_hash_attr_t;
--
local function variable_mtev_hash_cb(pt_var, bt_var)
  -- L("XXX variable_cb: name=%s, add=%x, type=%s base_type=%s",
  --   pt_var:name(), pt_var:address(), pt_var:type_name(), pt_var:base_type())
  local pt_hash = pt_var
  local map = bt2val(bt_var.u.hs.map) -- type: struct ck_hs_map
  if (map > 0) then
    local fr = pt_var:frame()
    local pt_map = pmodule.create_variable("<type>", "map (extracted)", 0, 0, pt_hash)
    pt_map:set_array()
    if fr then fr:add_variable(pt_map) end
    local n = poke_num(map+40, 4)
    local cap = poke_num(map+48, 4)
    local entr_p = poke_num(map+72, 8)
    local entr_l = poke_ptr_arr(entr_p, cap) -- list of pointers
    mkvar("filled (extracted)", n, pt_hash)
    mkvar("capacity (extracted)", cap, pt_hash)
    local cnt = 0
    for i, a_ent in ipairs(entr_l) do
      -- a_ent is a pointer to the key member of struct ck_hash_attr
      if a_ent > 0 then
        cnt = cnt + 1
        if cnt > LIMIT_MEMBER_COUNT then
          if fr then fr:annotate(pmodule.annotation.warning, "truncated map extraction") end
          break
        end
        local a_key  = a_ent - 8;
        local key = poke_val(deref(a_key), 100)
        local a_data = a_ent - 16;
        local data = poke_val(deref(a_data), 100)
        mkvar(key, data, pt_map)
      end
    end
  end
end

local function pm_mtev_hash_load()
  L("module-mtev-hash: load")
  local m = pmodule.match()
  m:add_variable_base_type("mtev_hash_table", pmodule.match_type.exact)
  pmodule.register(pmodule.event.variable, variable_mtev_hash_cb, m)
end

pmodule.define {
   id = "mtev_hash",
   load = pm_mtev_hash_load,
}
