-- flatten a kv table into a k=v array
function env_flatten(tbl)
  local nt = {}
  for k,v in pairs(tbl) do nt[#nt+1] = k .. "=" .. v end
  return nt
end

-- makes a basic corouting reader on an fd
function mk_coroutine_reader(start, done, fd)
  mtev.coroutine_spawn(function()
    local fd = fd:own()
    local output = ''
    mtev.waitfor(start,1)
    while true do
      local line = fd:read("\n")
      if line == nil then
        break
      end
      output = output .. line
    end
    mtev.notify(done, output)
    fd:close()
    return nil
  end)
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
  for k,v in pairs(props) do obj[k] = v end
  obj.timeout = obj.timeout or 5
  if obj.boot_match == nil then obj.boot_match = "eventer_loop%(%) started" end
  if obj.dir == nil then obj.dir = find_test_dir() end
  if obj.env == nil then
   obj.env = { UMEM_DEBUG = "default" }
   for k,v in pairs(ENV) do obj.env[k] = v end
   obj.env = env_flatten(obj.env)
  end

  obj.log_watchers = {}

  setmetatable(obj, TestProc)
  return obj
end

function TestProc:watchfor(f, many)
  local key = 'log-' .. mtev.uuid()
  self.log_watchers[key] = { matches = f, once = not many }
  return key
end

function TestProc:watchfor_stop(key)
  self.log_watchers[key] = nil
  repeat
    local rkey = mtev.waitfor(key, 0)
  until rkey == nil
end

function TestProc:waitfor(key, timeout)
  local rkey, line = mtev.waitfor(key, timeout)
  return line
end

function TestProc:capturecommand(props)
  if self.proc ~= nil then error("can't start already started proc") end
  local proc, in_e, out_e, err_e =
    mtev.spawn(self.path, self.argv, self.env)
  self.stdout_start, self.stderr_start = mtev.uuid(), mtev.uuid()
  self.stdout, self.stderr = mtev.uuid(), mtev.uuid()
  self.proc = proc
  if proc ~= nil then
    in_e:close()
    mk_coroutine_reader(self.stdout_start, self.stdout, out_e)
    mk_coroutine_reader(self.stderr_start, self.stderr, err_e)
  else
    error("cannot start proc")
  end
  mtev.notify(self.stdout_start, true)
  mtev.notify(self.stderr_start, true)

  local stdout_key, stdout_data = mtev.waitfor(self.stdout, self.timeout)
  local stderr_key, stderr_data = mtev.waitfor(self.stderr, self.timeout)

  local ret = self.proc:wait(1)

  if ret == nil then
    self.proc:kill()
    ret = self.proc:wait(10)
  end
  if ret == nil then
    error("Couldn't quit process")
  end

  self.proc = nil

  return stdout_data, stderr_data
end

function TestProc:start(props)
  if self.proc ~= nil then error("can't start already started proc") end
  local proc, in_e, out_e, err_e =
    mtev.spawn(self.path, self.argv, self.env)
  self.start, self.ready = mtev.uuid(), mtev.uuid()
  self.proc = proc
  if proc ~= nil then
    in_e:close()
    out_e:close()
    mtev.coroutine_spawn(function()
      local err_e = err_e:own()
      local started = false
      local logname = self.logname or self.argv[1]
      local outp = io.open(self.dir .. '/' .. logname .. ".out",  "wb")
      if outp == nil then
        error("Could not open: " .. self.dir .. '/' .. logname .. ".out")
      end
      mtev.waitfor(self.start,1)
      while true do
        local line = err_e:read("\n")
        if line == nil then
          if not started then mtev.notify(self.ready, false) end
          break
        end
        outp:write(line);
        outp:flush()
        for key, watcher in pairs(self.log_watchers) do
          watcher.matches(nil) -- reset the PCRE (if it is a PCRE)
          if watcher.matches(line) then
            mtev.notify(key, line)
            if watcher.once then
              self.log_watchers[key] = nil
            end
          end
        end
        if line:find(self.boot_match) and not started then
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
    self.proc:wait(10)
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
    proc:wait(100)
  end
end

function TestProc:wait(timeout)
  if self.proc == nil then return nil end
  return self.proc:wait(timeout)
end

function TestProc:kill()

  if self.proc == nil or self.proc:pid() == -1 then return end

  if TEST_OPTIONS['findleaks'] then self:find_leaks() end

  self.proc:kill()
  local waittime = 0
  local status = self.proc:wait(2)
  if status == nil then
    self.proc:kill(9)
    self.proc:wait(10)
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
function run_command_synchronously_return_output(props)
  local proc = TestProc:new(props)
  return proc:capturecommand()
end
function kill_child(child)
  child:kill()
end
