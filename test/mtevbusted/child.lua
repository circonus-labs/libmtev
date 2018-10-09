-- flatten a kv table into a k=v array
function env_flatten(tbl)
  local nt = {}
  for k,v in pairs(tbl) do nt[#nt+1] = k .. "=" .. v end
  return nt
end

-- Start and Stop

function find_test_dir()
  local lvl = 3
  local dir
  local cwd = mtev.getcwd()
  repeat
    dir = sourcedir(lvl)
    lvl = lvl+1
  until dir == nil or not (dir:match("^/") or dir:match("lua%-support/")) or lvl > 10
  return dir
end

-- This functionality of this class has been moved to mtev.Proc.
-- This class here is only a farcade.
-- Future tests should use mtev.Proc directly.
local TestProc = {}
TestProc.__index = TestProc

function TestProc:new(props)
  local self = setmetatable({}, TestProc)
  local p = { unpack(props) }
  p.boot_timeout = p.timeout or 5
  p.boot_match = p.boot_match or "eventer_loops started"
  p.dir = p.dir or find_test_dir()
  if p.env == nil then
    p.env = { UMEM_DEBUG = "default" }
    for k,v in pairs(ENV) do p.env[k] = v end
    p.env = env_flatten(p.env)
  end
  self.proc = mtev.Proc:new(p)
  --
  local logname = self.logname or self.argv[1]
  local logfile = self.dir .. '/' .. logname .. ".out"
  self:logwrite(logfile)
  return self
end

function TestProc:watchfor(f, many)
  local limit
  if not many then limit = 1 end
  return self.proc:logwatch(f, limit)
end

function TestProc:watchfor_stop(handler)
  handler:stop()
end

function TestProc:waitfor(handler, timeout)
  return handler:wait(timeout)
end

function TestProc:start()
  self.proc:start()
end

function TestProc:find_leaks()
  local proc, in_e, out_e, err_e =
    mtev.spawn("/bin/mdb", { "mdb", "-p", self.proc:pid() })
  local done = mtev.uuid()
  if proc ~= nil and proc:pid() ~= -1 then
    in_e:write("::findleaks -d\n")
    in_e:close()
    err_e:close()
    mtev.coroutine_spawn(function()
        local out_e = out_e:own()
        local outp = io.open(self.dir .. "findleaks." .. proc:pid(),  "wb")
        while true do
          local line = out_e:read("\n")
          if line == nil then
            mtev.notify(done, "EOF")
            break
          end
          outp:write(line)
        end
        outp:close()
        return nil
    end)
    local key, ok = mtev.waitfor(done,10)
    proc:wait(100)
  end
end

function TestProc:wait(timeout)
  local term, status, errno = self.proc:wait(timeout)
  return status, errno
end

function TestProc:pause()
  return self.proc:pause()
end

function TestProc:resume()
  return self.proc:resume()
end

function TestProc:kill()
  if TEST_OPTIONS['findleaks'] then self:find_leaks() end
  return self.proc:kill()
end

function TestProc:pid()
  return self.proc:pid()
end

function start_child(props)
  local proc = TestProc:new(props)
  proc:start()
  return proc
end

function run_command_synchronously_return_output(props)
  return mtev.exec(
    props.path,
    props.argv,
    props.env,
    props.timeout
  )
end

function kill_child(child)
  child:kill()
end
