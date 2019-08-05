local HTTP_HEAD = "POST %s HTTP/1.1\r\n" ..
  "Host: localhost:12345\r\n" ..
  "User-Agent: manual\r\n" ..
  "Transfer-Encoding: chunked\r\n" ..
  "Accept: */*\r\n" ..
  "\r\n"

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
  local port = 8888
  local timeout = 1
  local e = mtev.socket(host)
  assert.is_true(e:connect(host, port, timeout) == 0)
  return e
end

describe("http server", function()

  local p

  it("starts test_http_server", function()
    -- just in case
    mtev.sh("pkill -f test_http_server")
    mtev.sh("rm test_http_server.lock")
    p = mtev.Proc:new {
      path = "./test_http_server",
      argv = { "test_http_server", "-D", "-c", "test_http_server.conf" },
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

  it("stops test_http_server", function()
     assert.is_true(p:kill())
  end)

end)
