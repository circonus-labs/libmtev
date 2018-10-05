--
-- mtev.Api
--
-- Wrapper class for HTTP/HTTPS APIs
--
module("mtev.Api", package.seeall)

local HttpClient = require('mtev.HttpClient')

local function HTTP(method, host, port, uri, headers, payload, sslconfig)
  assert(method)
  assert(host)
  assert(port)
  local ssl = not not sslconfig -- convert to bool
  sslconfig = sslconfig or {}
  headers = headers or {}
  local in_headers = {}

  if type(payload) == "table" then
    payload = mtev.tojson(payload):tostring()
  end

  local dns = mtev.dns()
  if not dns.is_valid_ip(host) then
    local r = dns:lookup(host)
    if not r or r.a == nil then return -1, "DNS lookup failed" end
    host = r.a
  end

  local output_buf = {}
  local callbacks = {}
  callbacks.consume  = function(str) output_buf[#output_buf+1] = str end
  callbacks.headers  = function(hdrs) in_headers = hdrs end
  callbacks.certfile = function() return sslconfig.certificate_file end
  callbacks.keyfile  = function() return sslconfig.key_file end
  callbacks.cachain  = function() return sslconfig.ca_chain end
  callbacks.ciphers  = function() return sslconfig.ciphers end

  local client = HttpClient:new(callbacks)
  local rv, err = client:connect(host, port, ssl, host)
  if rv ~= 0 then return -1, "client:connect failed" end

  headers.Host = host
  if not headers.Accept then headers.Accept = 'application/json' end
  mtev.log("debug/http", "HTTP IN: %s\n", mtev.tojson({method, uri, headers, payload}):tostring())
  local rv = client:do_request(method, uri, headers, payload, "1.1")
  client:get_response(100000000) -- read limit
  local output = table.concat(output_buf)
  mtev.log("debug/http", "HTTP OUT: %s\n--\n%s\n", mtev.tojson({client.code, in_headers}):tostring(), output)
  return client.code, output, in_headers
end

--
-- Private Class: ApiResponse
--
local ApiResponse = {}
ApiResponse.__index = ApiResponse

function ApiResponse:new(code, output, headers)
  local self = {
    code = code,
    output = output,
    headers = headers,
  }
  return setmetatable(self, ApiResponse)
end

--/*!
--\lua rc = mtev.ApiResponse:rc()
--*/
function ApiResponse:rc()
  return self.code
end

--/*!
--\lua self = mtev.ApiResponse:check()
--\brief Raise and error unless rc == 200
--\return self
--*/
function ApiResponse:check()
  if self:rc() ~= 200 then
    error("API requests failed: " .. self.output)
  end
  return self
end

--/*!
--\lua text = mtev.ApiResponse:text()
--\brief return payload of response as string
--*/
function ApiResponse:text()
  return self.output
end

--/*!
--\lua t = mtev.ApiResponse:json()
--\return parsed payload of response as table t
--*/
function ApiResponse:json()
  local o = self.output
  if not o or o == '' then return nil end
  local doc, err, offset = mtev.parsejson(o)
  if doc == nil then
    error("json parse error: %s @%d\n", err, offset)
  end
  return doc:document()
end

--/*!
--\lua t = mtev.ApiResponse:xml()
--\return parsed payload of response as table mtev.xmldoc
--*/
function ApiResponse:xml()
  local o = self.output
  if not o or o == '' then return nil end
  local doc = mtev.parsexml(o)
  return doc
end

--
-- Class: API
--
Api = {}
Api.__index = Api


-- Direct use of this constructor is discouraged.
-- Use HTTP/HTTPS constructors instead.
-- Returns a new Api object
-- If sslconfig is given, all requests will use SSL/HTTPS
function Api:new(host, port, headers, sslconfig)
  local self = {}
  self.host = host or error("No host given")
  self.port = port or error("No port given")
  self.headers = headers
  self.sslconfig = sslconfig
  return setmetatable(self, Api)
end

--/*!
--\lua api = mtev.Api:http(host, port, [headers])
--\brief Wraps an HTTP Api
--
--Example:
--```
--local api = mtev.Api:http(host, port, [headers])
--local result_text = api:get("/"):check():text()
--local result_table = api:get("/"):check():json()
--```
--*/
function Api:http(host, port, headers)
  return Api:new(host, port, headers)
end

--/*!
--\lua api = mtev.Api:https(host, port, [headers], [sslconfig])
--\brief Wraps an HTTPS Api
--*/
function Api:https(host, port, headers, sslconfig)
  return Api:new(host, port, headers, sslconfig or {})
end

--/*!
--\lua api_response = mtev.Api:request(method, path, payload, [headers])
--\brief Issue a HTTP(S) request
--\return an mtev.ApiResponse object
--*/
function Api:request(method, path, payload, headers)
  headers = headers or self.headers
  return ApiResponse:new(
    HTTP(method, self.host, self.port, path, headers, payload, self.sslconfig)
  )
end

--/*!
--\lua api_response = mtev.Api:get(path, payload, headers)
--\brief Isse a GET request
--*/
function Api:get(...)
  return self:request("GET", ...)
end

--/*!
--\lua api_response = mtev.Api:post(path, payload, headers)
--\brief Issue a POST request
--*/
function Api:post(...)
  return self:request("POST", ...)
end

--/*!
--\lua api_response = mtev.Api:put(path, payload, headers)
--\brief Issue a PUT request
--*/
function Api:put(...)
  return self:request("PUT", ...)
end

return Api
