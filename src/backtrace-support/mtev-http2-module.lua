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

local function variable_http2_cb(pt_var, bt_var)
  local tid = pt_var:thread():tid()
  local method = bt2str(bt_var.method_str)
  local uri = bt2str(bt_var.uri_str)
  local qs = bt2str(bt_var.orig_qs)
  qs = qs and ("?" .. qs) or ""
  local length = bt2val(bt_var.content_length) or -1
  pt_var:thread():annotate(
    pmodule.annotation.comment,
    string.format("mtev_http2_request: %s %s%s (%d)", method, uri, qs, length))
  pt_var:backtrace():add_kv_string(
    "mtev_http_request",
    string.format("%s %s%s (%d)", method, uri, qs, length))
end

local function pm_mtev_http2_req()
  L("module-mtev-http2: load")
  local m = pmodule.match()
  m:add_file("mtev_http", pmodule.match_type.substr)
  m:add_variable_base_type("mtev_http2_request", pmodule.match_type.exact)
  pmodule.register(pmodule.event.variable, variable_http2_cb, m)
end

pmodule.define {
  id = "mtev_http2_req",
  load = pm_mtev_http2_req,
}
