-- relative to /test directory
local EXAMPLE_DIR = "../src/examples/"

function tohex(str)
  return (str:gsub('.', function (c) return string.format('0x%02X ', string.byte(c)) end))
end

local HTTP_HEAD = "POST / HTTP/1.1\r\n" ..
  "Host: localhost:12345\r\n" ..
  "User-Agent: manual\r\n" ..
  "Transfer-Encoding: chunked\r\n" ..
  "Accept: */*\r\n" ..
  "\r\n"

local function echo_write_head(e)
  -- print("> ", tohex(HTTP_HEAD))
  e:write(HTTP_HEAD)
end

local function echo_write_chunk(e, sz)
  local t = {}
  for i = 1, sz do
    t[i] = "x"
  end
  local p = string.format("%x\r\n%s\r\n", sz, table.concat(t))
  -- print("> ", tohex(p))
  e:write(p)
end

local function echo_write_term(e)
  e:write("0\r\n\r\n")
end

local function echo_read(e)
  local head = e:read("\r\n\r\n")
  print("HEAD", head)
  -- payload may or may not be chunk encoded. We just want to pick out the HASH value
  -- E.g. "HASH 123132"
  local payload = e:read(100000)
  print("PAYLOAD", payload)
  assert(payload)
  local hash
  payload:gsub("HASH (%d+)",function(s) hash = tonumber(s) end)
  return hash
end

local function echo_connect()
  local host = "127.0.0.1"
  local port = 8888
  local timeout = 1
  local e = mtev.socket(host)
  assert.is_true(e:connect(host, port, timeout) == 0)
  return e
end

describe("http server", function()

  local p
  it("starts echo_server", function()
    --  just in case
    mtev.sh("pkill echo_server")
    p = mtev.Proc:new {
      path = EXAMPLE_DIR .. "echo_server",
      argv = { "echo_server", "-D", "-x", "-c", EXAMPLE_DIR .. "echo_server.conf" },
      boot_match = "Ready.",
    }
    p:loglog("error")
    assert.is_true(p:start():ready())
  end)

  it("Should respond", function()
    local e = echo_connect()
    echo_write_head(e)
    echo_write_term(e)
    local hash = echo_read(e)
    assert(hash == 5381)
  end)

  it("Should handle specific chunks sizes", function()
     local e = echo_connect()
     echo_write_head(e)
     -- echo_write_chunk(e, 65524)
     -- echo_write_chunk(e, 65524)
     -- echo_write_chunk(e, 65524)
     -- echo_write_chunk(e, 65524)
     -- echo_write_chunk(e, 65524)
     -- echo_write_chunk(e, 65524)
     echo_write_chunk(e, 32694)
     echo_write_term(e)
     local hash = echo_read(e)
     print(hash)
     os.exit(1)
  end)

  it("Should accept chunked payloads", function()
     local e = echo_connect()
     echo_write_head(e)
     for i = 65500, 65700, 5 do
       echo_write_chunk(e, i)
     end
     echo_write_term(e)
     local hash = echo_read(e)
     print(hash)
  end)

  it("stops echo_server", function()
     assert.is_true(p:kill())
  end)

end)
