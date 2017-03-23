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
  until not (dir:match("^/") or dir:match("lua%-support/")) or lvl > 10
  return dir
end

local TestProc = {}
TestProc.__index = TestProc

function TestProc:new(props)
  local obj = {}
  obj.path = props.path
  obj.args = props.argv
  obj.env = props.env
  obj.gatestr = props.boot_match
  obj.timeout = props.timeout or 5
  obj.dir = props.dir
  if obj.dir == nil then obj.dir = find_test_dir() end
  if obj.env == nil then
   obj.env = { UMEM_DEBUG = "default" }
   for k,v in pairs(ENV) do obj.env[k] = v end
   obj.env = env_flatten(obj.env)
  end
  if obj.gatestr == nil then obj.gatestr = "eventer_loop%(%) started" end
  setmetatable(obj, TestProc)
  return obj
end
  
function TestProc:start(props)
  if self.proc ~= nil then error("can't start already started proc") end
  local proc, in_e, out_e, err_e =
    mtev.spawn(self.path, self.args, self.env)
  self.start, self.ready = mtev.uuid(), mtev.uuid()
  self.proc = proc
  if proc ~= nil then
    in_e:close()
    out_e:close()
    mtev.coroutine_spawn(function()
      local err_e = err_e:own()
      local started = false
      local outp = io.open(self.dir .. '/' .. self.args[1] .. ".out",  "wb")
      if outp == nil then
        error("Could not open: " .. self.dir .. '/' .. self.args[1] .. ".out")
      end
      mtev.waitfor(self.start,1)
      while true do
        local line = err_e:read("\n")
        if line == nil then
          if not started then mtev.notify(self.ready, false) end
          break
        end
        outp:write(line);
        if line:find(self.gatestr) and not started then
          mtev.notify(self.ready, true)
          started = true
        end
      end
      outp:close()
      return nil
    end)
  else
   error("cannot start proc")
  end
  mtev.notify(self.start, true)
  local key, ok = mtev.waitfor(self.ready,self.timeout)
  if ok then
    -- started
  else
    self.proc:kill()
    self.proc:wait()
    self.proc = nil
    return nil
  end
  return self 
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
    while proc:wait() == nil do mtev.sleep(0.01) end
  end
end

function TestProc:kill()

  if TEST_OPTIONS['findleaks'] then self:ind_leaks() end

  self.proc:kill()
  local waittime = 0
  while true do
    local status = self.proc:wait()
    if status ~= nil or waittime > 2 then break end
    waittime = waittime + mtev.sleep(0.01)
  end
  if status == nil then
    self.proc:kill(9)
    while true do
      if self.proc:wait() == nil then break end
      mtev.sleep(0.01)
    end
  end
end

function TestProc:pid()
  if self.proc == nil then return -1 end
  return self.proc:pid()
end

function start_child(props)
  local proc = TestProc:new(props)
  proc:start()
  return proc
end
function kill_child(child)
  child:kill()
end
