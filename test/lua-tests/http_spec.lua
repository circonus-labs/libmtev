local HTTP_HEAD = "POST %s HTTP/1.1\r\n" ..
  "Host: localhost:12345\r\n" ..
  "User-Agent: manual\r\n" ..
  "Transfer-Encoding: chunked\r\n" ..
  "Accept: */*\r\n" ..
  "\r\n"

math.randomseed(mtev.getpid())
local port = math.floor(20000 + math.random(10000))
local tlsport = port + 1
local curl_connect = table.concat({"test-server", "443", "localhost", tlsport}, ":")
local curl_ssl = { "--connect-to", curl_connect, "--cacert", "demoCA/root/certs/ca.crt" }
local api = API:new("localhost", tlsport):ssl({
  ca_file = "demoCA/root/certs/ca.crt",
  key = "test-client.key",
  certificate = "test-client.crt",
  snihost = "test-server"
})

local function hash_xlen(l)
  local h = 5381
  local x = ("x"):byte() -- 120
  local MOD = 2^32
  for i = 1, l do
    h = (h * 33 + x) % MOD
  end
  return h
end

local function srv_write_head(e, path)
  e:write(string.format(HTTP_HEAD, path or "/"))
end

local function srv_write_chunks(e, sizes, int, delay)
  local out = {}
  local h = nil
  for _, sz in ipairs(sizes) do
    local t = {}
    for i = 1, sz do
      t[i] = "x"
    end
    out[#out+1] = string.format("%x\r\n%s\r\n", sz, table.concat(t))
  end
  p = table.concat(out)
  -- print("> ", tohex(p))
  if not int then
    e:write(p)
  else
    for i=1,p:len(),int do
      local part = p:sub(i, math.min(i+int-1,p:len()))
      e:write(part)
      if delay then mtev.sleep(delay) end
    end
  end
  return h
end

local function srv_write_term(e)
  e:write("0\r\n\r\n")
end

local function srv_read(e)
  local head = e:read("\r\n\r\n", nil, 1, function() end)
  -- payload may or may not be chunk encoded. We just want to pick out the HASH value
  -- E.g. "HASH 123132"
  local payload = e:read(100000, nil, 1, function() end)
  assert(payload)
  local hash
  payload:gsub("HASH (%d+)",function(s) hash = tonumber(s) end)
  return hash
end

local function srv_connect()
  local host = "127.0.0.1"
  local timeout = 1
  local e = mtev.socket(host)
  assert.is_true(e:connect(host, port, timeout) == 0)
  return e
end

function http(url)
  return "http://127.0.0.1:" .. tostring(port) .. url
end

function https(url)
  return "https://test-server" .. url
end

function map(arr, f)
  local o = {}
  for _, v in ipairs(arr) do table.insert(o, f(v)) end
  return o
end

function json(data)
  local doc, err = mtev.parsejson(data)
  return doc and doc:document() or nil
end
function xml(data)
  return mtev.parsexml(data)
end
function identity(d) return d end

function curl(method, url, transform, curl_params)
  curl_params = curl_params or {}
  local cmd = "curl -D- -s -X " .. method .. " " .. table.concat(curl_params, " ") .. " " .. url
  local ret, out, err = mtev.sh(cmd)
  local meta = {}
  local i,j = string.find(out or "", '\r\n\r\n')
  if i ~= nil then
    local hdr, hdrs
    repeat
      hdr = string.sub(out, 1, i)
      out = string.sub(out, j+1)
      hdrs = mtev.extras.split(hdr, "\r\n")
      meta.protocol, meta.code, meta.msg = string.match(hdrs[1], "(%S+)%s+(%S+)%s+(%S*)")
      meta.code = tonumber(meta.code)
      i,j = string.find(out or "", '\r\n\r\n')
    until meta.code ~= 101 or i == nil
    if #hdrs > 1 then
      for i = 2,#hdrs do
        hdrs[i] = hdrs[i]:gsub("[\r\n]*$", "")
        local key, val = hdrs[i]:match("([^:]+):%s*(.*)")
        meta[string.lower(key)] = val
      end
    end
  end
  local doc = transform(out)
  return cmd, meta, doc
end

describe("http server", function()

  local p

  it("starts test_http_server", function()
    -- just in case
    mtev.sh("pkill -f test_http_server")
    mtev.sh("rm test_http_server.lock")
    local env = {}
    for k,v in pairs(ENV) do env[k] = v end
    env["LOCKFILE"] = mtev.getcwd() .. "/test_http_server.lock"
    env["PORT"] = port
    env["TLSPORT"] = tlsport
    p = mtev.Proc:new {
      path = "./test_http_server",
      argv = { "test_http_server", "-D", "-c", "test_http_server.conf" },
      env = env,
      boot_match = "Ready.",
    }
    p:logwrite("test_http_server.out")
    p:start()
    assert.is_true(p:ready())
  end)

  it("Should respond", function()
       local e = srv_connect()
       srv_write_head(e)
       srv_write_term(e)
       local hash = srv_read(e)
       assert(hash == 5381)
  end)

  it("works with HttpClient", function()
    local code, obj = api:HTTPS("GET", "/capa.json")
    assert.is_equal(200, code)
    assert.is_not_nil(obj)
    assert.is_not_nil(obj.version)
  end)

  local curl_work = {
    { method = "GET",
      params = { { "--http1.1", unpack(curl_ssl) } },
      transform = xml,
      urls = map({
        "/capa"
      }, https),
      expect = 200
    },
    { method = "CAPA",
      tranform = xml,
      params = { { "--no-alpn", "--no-npn", "--http0.9", unpack(curl_ssl) } },
      urls = map({'/'}, https)
    },
    { method = "GET",
      params = {
        { "--http0.9" },
        { "--http1.0" },
        { "--http1.1" },
        { "--compressed --http2" },
      },
      transform = json,
      urls = map({
        "/capa.json", "/mtev/stats.json", "/mtev/memory.json",
        "/eventer/memory.json", "/eventer/sockets.json", "/eventer/jobq.json",
        "/eventer/timers.json", "/mtev/rest.json",
        "/eventer/logs/internal.json", "/eventer/logs/internal.json\\?since=0",
      }, http),
      expect = 200
    },
    { method = "GET",
      params = {
        { "--http0.9" },
        { "--http1.0" },
        { "--http1.1" },
        { "--compressed --http2" },
      },
      transform = json,
      urls = map({
        "/eventer/logs/nope.json"
      }, http),
      expect = 404
    },
    { method = "GET",
      params = {
        { "--http1.0", unpack(curl_ssl) },
        { "--http1.1", unpack(curl_ssl) },
        { "--compressed", "--http2", unpack(curl_ssl) },
      },
      transform = json,
      urls = map({
        "/capa.json", "/mtev/stats.json", "/mtev/memory.json",
        "/eventer/memory.json", "/eventer/sockets.json", "/eventer/jobq.json",
        "/eventer/timers.json", "/eventer/logs/internal.json",
	"/mtev/rest.json",
      }, https),
      expect = 200
    },
    { method = "GET",
      params = {
        { "--http1.0", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
        { "--http1.1", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
        { "--compressed", "--http2", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
      },
      urls = map({
        "/client-required"
      }, https),
      expect = 200
    },
    { method = "GET",
      params = {
        { "--http1.0", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
        { "--http1.1", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
        { "--compressed", "--http2", "--key", "test-client.key", "--cert", "test-client.crt", unpack(curl_ssl) },
      },
      urls = map({
        "/server-required"
      }, https),
      expect = 403
    },
  }

  describe("curl", function()
    it("curl excercise", function()
      for _, set in ipairs(curl_work) do
        for _, params in ipairs(set.params) do
          for _, url in ipairs(set.urls) do
            local cmd, meta, out = curl(set.method, url, set.transform or identity, params)
            if set.expect ~= nil then
              assert.message(cmd).is.equal(set.expect, meta.code)
            end
            assert.message(cmd).is.not_nil(out)
          end
        end
      end
    end)
  end)

  describe("lz4f transfer encoding", function()
    it("fetches", function()
      local rv, out = mtev.sh("./geturllz4f " .. http("/capa.json"))
      assert.is_equal(0, rv)
      local obj = json(out)
      assert.is_not_nil(obj)
      assert.is_not_nil(obj.version)
    end)
  end)

  describe("non ACO", function()
    it("Should read to small chunks in one go", function()
         local e = srv_connect()
         srv_write_head(e, "/?readsize=10000&delay=.001")
         local N = 10
         local C = {}
         for i = 1, N do C[i] = i end
         srv_write_chunks(e, C, 1)
         srv_write_term(e)
         local hash = srv_read(e)
         assert.is_equal(hash, hash_xlen(N * (N+1) / 2))
    end)

    it("Should read to small chunks one byte at a time", function()
         local e = srv_connect()
         srv_write_head(e, "/?readsize=1&delay=.001")
         local N = 10
         local C = {}
         for i = 1, N do C[i] = i end
         srv_write_chunks(e, C, 1)
         srv_write_term(e)
         local hash = srv_read(e)
         assert.is_equal(hash, hash_xlen(N * (N+1) / 2))
    end)

    it("Should read large chunks", function()
         local e = srv_connect()
         srv_write_head(e, "/?readsize=1000")
         srv_write_chunks(e, {1024, 1024*10, 1024*100, 1024*1000}, 100)
         srv_write_term(e)
         mtev.sleep(.1)
         local hash = srv_read(e)
         assert.is_equal(hash,hash_xlen(1024*(1111)))
    end)

    it("Should handle chunks sizes which at the buffer boundary", function()
      local BSZ = 32704
      for delta = -20, 0, 3 do
        local e = srv_connect()
        srv_write_head(e)
        srv_write_chunks(e, {BSZ + delta})
        srv_write_term(e)
        local hash = srv_read(e)
        assert.is_equal(hash, hash_xlen(BSZ + delta))
      end
    end)
  end)

  describe("aco", function()
    it("Should read to small chunks in one go", function()
         local e = srv_connect()
         srv_write_head(e, "/aco?readsize=10000&delay=.001")
         local N = 10
         local C = {}
         for i = 1, N do C[i] = i end
         srv_write_chunks(e, C, 1)
         srv_write_term(e)
         local hash = srv_read(e)
         assert.is_equal(hash, hash_xlen(N * (N+1) / 2))
    end)

    it("Should read to small chunks one byte at a time", function()
         local e = srv_connect()
         srv_write_head(e, "/aco?readsize=1&delay=.001")
         local N = 10
         local C = {}
         for i = 1, N do C[i] = i end
         srv_write_chunks(e, C, 1)
         srv_write_term(e)
         local hash = srv_read(e)
         assert.is_equal(hash, hash_xlen(N * (N+1) / 2))
    end)

    it("Should read large chunks", function()
         local e = srv_connect()
         srv_write_head(e, "/aco?readsize=1000")
         srv_write_chunks(e, {1024, 1024*10, 1024*100, 1024*1000}, 100)
         srv_write_term(e)
         mtev.sleep(.1)
         local hash = srv_read(e)
         assert.is_equal(hash,hash_xlen(1024*(1111)))
    end)

    it("Should handle chunks sizes which at the buffer boundary", function()
      local BSZ = 32704
      for delta = -20, 0, 3 do
        local e = srv_connect()
        srv_write_head(e, "/aco")
        srv_write_chunks(e, {BSZ + delta})
        srv_write_term(e)
        local hash = srv_read(e)
        assert.is_equal(hash, hash_xlen(BSZ + delta))
      end
    end)
  end)

  it("stops test_http_server", function()
     assert.is_true(p:kill())
  end)

end)
