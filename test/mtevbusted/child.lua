-- flatten a kv table into a k=v array
function env_flatten(tbl)
  local nt = {}
  for k,v in pairs(tbl) do nt[#nt+1] = k .. "=" .. v end
  return nt
end

-- Start and Stop

local function find_src_dir()
  local lvl = 3
  local dir
  local cwd = mtev.getcwd()
  repeat
    dir = sourcedir(lvl)
    lvl = lvl+1
  until not (dir:match("^/") or dir:match("lua%-support/")) or lvl > 10
  return dir
end

function start_child(props)
  local path = props.path
  local args = props.argv
  local env = props.env
  local gatestr = props.boot_match
  local timeout = props.timeout or 5
  local dir = dir
  if dir == nil then dir = find_src_dir() end
  if env == nil then
   env = { UMEM_DEBUG = "default" }
   for k,v in pairs(ENV) do env[k] = v end
   env = env_flatten(env)
  end
  if gatestr == nil then gatestr = "eventer_loop%(%) started" end
  local proc, in_e, out_e, err_e =
    mtev.spawn(path, args, env)
  local start, ready = mtev.uuid(), mtev.uuid()
  if proc ~= nil then
    in_e:close()
    out_e:close()
    mtev.coroutine_spawn(function()
      local err_e = err_e:own()
      local started = false
      local outp = io.open(dir .. args[1] .. ".out",  "wb")
      if outp == nil then
        error("Coult not open: " .. dir .. args[1] .. ".out")
      end
      mtev.waitfor(start,1)
      while true do
        local line = err_e:read("\n")
        if line == nil then
          if not started then mtev.notify(ready, false) end
          break
        end
        outp:write(line);
        if line:find(gatestr) and not started then
          mtev.notify(ready, true)
          started = true
        end
      end
      outp:close()
      return nil
    end)
  end
  mtev.notify(start, true)
  local key, ok = mtev.waitfor(ready,timeout)
  if not ok then
    proc:kill()
    proc:wait()
    return nil
  end
  return proc
end

function kill_child(child)
  local proc, in_e, out_e, err_e =
    mtev.spawn("/bin/mdb", { "mdb", "-p", child:pid() })
  local done = mtev.uuid(), mtev.uuid()
  if proc ~= nil and proc:pid() ~= -1 then
    in_e:write("::findleaks -d\n")
    in_e:close()
    err_e:close()
    local dir = find_src_dir()
    mtev.coroutine_spawn(function()
        local out_e = out_e:own()
        local outp = io.open(dir .. "findleaks",  "wb")
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
  child:kill()
  local waittime = 0
  while true do
    local status = child:wait()
    if status ~= nil or waittime > 2 then break end
    waittime = waittime + mtev.sleep(0.01)
  end
  if status == nil then
    child:kill(9)
    while true do
      if child:wait() == nil then break end
      mtev.sleep(0.01)
    end
  end
end
