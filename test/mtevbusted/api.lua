local apihost
local apiport

local HttpClient = require('mtev.HttpClient')

function set_api_host(host) apihost = host end
function set_api_port(port) apiport = port end

function sourcefile(lvl)
  if lvl == nil then lvl = 2 end
  local src = debug.getinfo(lvl).source
  if src == nil then return nil end
  if src:sub(1,1) == "@" then return src:sub(2) end
  return src
end

function sourcedir(lvl)
  if lvl == nil then lvl = 2 end
  local src = debug.getinfo(lvl).source
  if src == nil then return nil end
  if src:sub(1,1) == "@" then src = src:sub(2) end
  local idx = src:find("/[^/]+$")
  if idx < 1 then return nil end
  return src:sub(1,idx)
end

function _file(name)
  local inp = io.open(sourcedir(3) .. name,  "rb")
  if inp == nil then return nil end
  local data = inp:read("*all")
  inp:close();
  return data
end

function _filejson(name)
  local inp = io.open(sourcedir(3) .. name,  "rb")
  if inp == nil then return nil end
  local data = inp:read("*all")
  inp:close();
  local doc, err = mtev.parsejson(data)
  if doc == nil then return nil, err end
  return doc:document()
end

API = {};
API.__index = API;
function API:new(host, port)
  local obj = { host = host or apihost,
                port = port or apiport }
  setmetatable(obj, API)
  return obj
end
function API:headers(headers)
  self.headers = headers or {}
  return self
end
function API:HTTP(method, uri, payload, _pp)
  return HTTP(method, self.host, self.port, uri, self.headers, payload, _pp)
end

function HTTP(method, host, port, uri, headers, payload, _pp)
  _pp = _pp or function(o)
    local doc, err, offset = mtev.parsejson(o)
    if doc == nil then
      mtev.log("error", "json parse error: %s @%d\n", err, offset)
      return nil
    end
    return doc:document()
  end
  local host = host or apihost
  local port = port or apiport
  headers = headers or {}
  local in_headers = {}

  if type(payload) == "table" then
    payload = mtev.tojson(payload):tostring()
  end

  local dns = mtev.dns()
  if not dns.is_valid_ip(host) then
    local r = dns:lookup(host)
    if not r or r.a == nil then return -1, { error = "lookup failed" } end
    host = r.a
  end

  local output_buf = {}
  local callbacks = {}
  callbacks.consume = function (str) output_buf[#output_buf+1] =  str end
  callbacks.headers = function (hdrs) in_headers = hdrs end

  local client = HttpClient:new(callbacks)
  local rv, err = client:connect(host, port, false, host)
  if rv ~= 0 then return -1, { error =  "client:connect failed" } end

  headers.Host = host
  headers.Accept = 'application/json'
  mtev.log("debug/http", "%s\n", mtev.tojson({method, uri, headers, payload}):tostring())
  local rv = client:do_request(method, uri, headers, payload, "1.1")
  client:get_response(100000000)
  local output = table.concat(output_buf)
  mtev.log("debug/http/out", "%s\n\n", output)
  return client.code, _pp(output), output
end

