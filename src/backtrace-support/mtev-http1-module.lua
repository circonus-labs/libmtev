function L(...)
  pmodule.log(pmodule.log_level.info, string.format(...))
end

local function bt2str(bt_var, len)
  len = len or 256
  local addr = pmodule.variable_from_bt(bt_var):value()
  return pmodule.address_read_string(addr, len)
end

local function bt2val(bt_var)
  return pmodule.variable_from_bt(bt_var):value()
end

local function variable_http1_cb(pt_var, bt_var)
  -- L("XXX variable_cb: name=%s, add=%x, type=%s base_type=%s",
  --   pt_var:name(), pt_var:address(), pt_var:type_name(), pt_var:base_type())
  local tid = pt_var:thread():tid()
  local method = bt2str(bt_var.method_str)
  local uri = bt2str(bt_var.uri_str)
  local qs = bt2str(bt_var.orig_qs)
  qs = qs and ("?" .. qs) or ""
  local length = bt2val(bt_var.content_length) or -1
  local payload_len = bt2val(bt_var.upload.size)
  local payload = "(empty)"
  if payload_len > 0 then
    payload = bt2str(bt_var.upload.data, payload_len + 1)
    if payload:match '[^ -~\n\t]' then     
      payload = "(binary data)"
    end
  end
  pt_var:thread():annotate(
    pmodule.annotation.comment,
    string.format("mtev_http1_request: %s %s%s (%d)", method, uri, qs, length))
  pt_var:backtrace():add_kv_string(
    "mtev_http_request",
    string.format("%s %s%s (%d)", method, uri, qs, length))
  pt_var:backtrace():add_kv_string(
    "mtev_http_payload_in",
    string.format("%s", payload))
end

function pm_mtev_http1_req()
  L("module-mtev-http1: load")
  local m = pmodule.match()
  m:add_file("mtev_http", pmodule.match_type.substr)
  m:add_variable_base_type("mtev_http1_request", pmodule.match_type.exact)
  pmodule.register(pmodule.event.variable, variable_http1_cb, m)
end

pmodule.define {
  id = "mtev_http1_req",
  load = pm_mtev_http1_req,
}
