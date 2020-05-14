local HTTP_HEAD = "POST %s HTTP/1.1\r\n" ..
  "Host: localhost:12345\r\n" ..
  "User-Agent: manual\r\n" ..
  "Transfer-Encoding: chunked\r\n" ..
  "Accept: */*\r\n" ..
  "\r\n"

local port = math.floor(20000 + math.random(10000))

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
  return "https://127.0.0.1:" .. tostring(port+1) .. url
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
  local cmd = "curl -s -X " .. method .. " " .. table.concat(curl_params, " ") .. " " .. url
  local ret, out, err = mtev.sh(cmd)
  local doc = transform(out)
  return cmd, ret, doc
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
    env["TLSPORT"] = port + 1
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

  local curl_work = {
    { method = "GET",
      params = { { "-k", "--http1.1" } },
      transform = xml,
      urls = map({
        "/capa"
      }, https)
    },
    { method = "CAPA",
      tranform = xml,
      params = { { "-k", "--no-alpn", "--no-npn", "--http0.9" } },
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
        "/eventer/timers.json",
        "/eventer/logs/nope.json", "/eventer/logs/internal.json",
        "/eventer/logs/internal.json\\?since=0",
	"/mtev/rest.json",
      }, http)
    },
    { method = "GET",
      params = {
        { "-k", "--http1.0" },
        { "-k", "--http1.1" },
        { "-k", "--compressed", "--http2" },
      },
      transform = json,
      urls = map({
        "/capa.json", "/mtev/stats.json", "/mtev/memory.json",
        "/eventer/memory.json", "/eventer/sockets.json", "/eventer/jobq.json",
        "/eventer/timers.json", "/eventer/logs/internal.json",
	"/mtev/rest.json",
      }, https)
    }
  }

  describe("curl", function()
    it("curl excercise", function()
      for _, set in ipairs(curl_work) do
        for _, params in ipairs(set.params) do
          for _, url in ipairs(set.urls) do
            local cmd, ret, out = curl(set.method, url, set.transform or identity, params)
            assert.message(cmd).is.equal(0, ret)
            assert.message(cmd).is.not_nil(out)
          end
        end
      end
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
