--
-- mtev.Proc
--
-- Wrapper class for external processes
--

-- flatten a table into a k=v array
local function env_flatten(tbl)
  local nt = {}
  for k,v in pairs(tbl) do nt[#nt+1] = k .. "=" .. v end
  return nt
end

-- makes a basic coroutine reader on an fd
local function mk_coroutine_reader(start, done, fd)
  mtev.coroutine_spawn(function()
    local fd = fd:own()
    local output = {}
    mtev.waitfor(start, 1)
    while true do
      local line = fd:read("\n")
      if line == nil then
        break
      end
      output[#output+1] = line
    end
    mtev.notify(done, table.concat(output))
    fd:close()
    return nil
  end)
end

--
-- Class: WatchHandler
--
local WatchHandler = {}
WatchHandler.__index = WatchHandler

function WatchHandler:new(proc, key)
  local o = {}
  o.proc = proc
  o.key = key
  return setmetatable(o, self)
end

--/*!
--\hlua line = mtev.LogWatch:wait(timeout)
--\brief wait for match
--\param timeout maximial time to wait in seconds
--\return line matched or nil on timeout
--*/
function WatchHandler:wait(timeout)
  local rkey, line = mtev.waitfor(self.key, timeout)
  return line
end

--/*!
--\hlua mtev.LogWatch:stop()
--\brief stop watching, drain watch queue
--*/
function WatchHandler:stop()
  o.proc.log_watchers[self.key] = nil
  repeat
    local rkey = mtev.waitfor(self.key, 0)
  until rkey == nil
end

--
-- Class mtev.Proc
--
local Proc = {}
Proc.__index = Proc

--/*!
--\hlua proc = mtev.Proc:new(opts)
--\brief Create and control a subprocess
--\param opts.path path of the executable
--\param opts.argv list of command line arguments (including process name)
--\param opts.dir working directory of the process, defaults to CWD
--\param opts.env table with environment variables, defaults to ENV
--\param opts.boot_match message that signals readiness of process
--\param opts.boot_timeout time to wait until boot_match appars in stderr in seconds, defaults to 5s
--\return a Proc object
--*/
function Proc:new(opts)
  local self = {}
  self.path = opts.path or error("path not set")
  self.argv = opts.argv or { self.path }
  self.dir = opts.dir or mtev.getcwd()
  if opts.env then
    self.env = opts.env
  else
    -- copy ENV
    self.env = {}
   for k,v in pairs(ENV) do self.env[k] = v end
  end
  self.env = env_flatten(self.env or {})
  self.boot_match = opts.boot_match or "ready"
  self.boot_timeout = opts.boot_timeout or 5
  self.log_watchers = {}
  self.log_writers = {}
  self.hook_term = {}
  return setmetatable(self, Proc)
end

--/*!
--\hlua watch = mtev.Proc:logwatch(regex, [limit])
--\brief Watch stderr for a line maching regexp
--\param regex is either a regex string or a function that consumes lines
--\param limit is the maximal number of matches to find. Default infinite.
--\return watch an mtev.LogWatch object
--*/
function Proc:logwatch(regex, limit)
  assert(regex)
  limit = limit or false
  local f
  if type(regex) == "string" then
    local re = mtev.pcre(regex)
    f = function(line)
      re() -- reset regex
      return re(line)
    end
  elseif type(regex) == "function" then
    f = regex
  else
    error("Illegal argument for Proc:watchfor(regex)")
  end
  local key = 'logwatch-' .. mtev.uuid()
  self.log_watchers[key] = { matches = f, limit = limit }
  return WatchHandler:new(self, key)
end

--/*!
--\hlua self = mtev.Proc:loglisten(f)
--\brief Execute f on each line emitted to stderr
--*/
function Proc:loglisten(func)
  table.insert(self.log_writers, func)
  return self
end

--/*!
--\hlua self = mtev.Proc:loglog(stream, [prefix])
--\brief Forward process output on stderr to mtev log stream
--*/
function Proc:loglog(stream, prefix)
  assert(stream)
  local prefix = prefix or ""
  local fmt = prefix .. "%s"
  local writer = function(line)
    mtev.log(stream, fmt, line)
  end
  self:loglisten(writer)
  return self
end

--/*!
--\hlua self = mtev.Proc:logwrite(file)
--\brief Write process output on stderr to file
--*/
function Proc:logwrite(file)
  local outp = io.open(self.dir .. '/' .. file,  "wb")
  if outp == nil then
    error("Could not open: " .. self.dir .. '/' .. file)
  end
  local writer = function(line)
    outp:write(line)
    outp:flush()
  end
  local close = function()
    outp:close()
  end
  self:loglisten(writer)
  table.insert(self.hook_term, close)
  return self
end

--/*!
--\hlua ok, msg = mtev.Proc:start()
--\brief start process
--\return self
--*/
function Proc:start()
  if self.proc ~= nil then error("can't start already started proc") end
  local proc, in_e, out_e, err_e =
    mtev.spawn(self.path, self.argv, self.env)
  if not proc then
    error("Could not start process")
  end
  self.proc = proc
  in_e:close()
  out_e:close()
  self.key_ready = mtev.uuid()
  mtev.coroutine_spawn(function()
      local err_e = err_e:own()
      local started = false
      while true do
        local line = err_e:read("\n")
        if line == nil then
          if not started then mtev.notify(self.key_ready, false) end
          break
        end
        for _, write in ipairs(self.log_writers) do
          write(line)
        end
        for key, watcher in pairs(self.log_watchers) do
          if watcher.matches(line) then
            mtev.notify(key, line)
            if watcher.limit then
              watcher.limit = watcher.limit - 1
              if watcher.limit <= 0 then
                self.log_watchers[key] = nil
              end
            end
          end
        end
        if not started and line:find(self.boot_match) then
          mtev.notify(self.key_ready, true)
          started = true
        end
      end
      for _, hook in ipairs(self.hook_term) do
        hook()
      end
      return
  end)
  return self
end

--/*!
--\lua status = Proc:ready(timeout)
--\brief wait for the process to become ready
--\return status true/false depending on weather the process became ready
--Cleans up process that did not become ready
--*/
function Proc:ready()
  local key, ok = mtev.waitfor(self.key_ready, self.boot_timeout)
  if not ok then -- cleanup process that could not start
    self.proc:kill()
    self.proc:wait(10)
    self.proc = nil
    return false
  end
  return true
end

--/*!
--\hlua pid = mtev.Proc:pid()
--*/
function Proc:pid()
  if self.proc == nil then return -1 end
  return self.proc:pid()
end

--/*!
--\hlua status = mtev.Proc:wait(timeout)
--\brief wait for a process to exit
--*/
function Proc:wait(timeout)
  if self.proc == nil then return nil end
  return self.proc:wait(timeout)
end

--/*!
--\hlua status = mtev.Proc:pause()
--\brief send SIGSTOP signal
--*/
function Proc:pause()
  if self.proc == nil or self.proc:pid() == -1 then return end
  self.proc:pgkill(19)
end

--/*!
--\hlua status = mtev.Proc:resume()
--\brief send SIGCONT signal
--*/
function Proc:resume()
  if self.proc == nil or self.proc:pid() == -1 then return end
  self.proc:pgkill(18)
end

return Proc
