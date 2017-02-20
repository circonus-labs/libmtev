-- Start and Stop

function start_child(path, args, env, gatestr)
  if env == nil then env = { "UMEM_DEBUG=default" } end
  if gatestr == nil then gatestr = "booted" end
  local proc, in_e, out_e, err_e =
    mtev.spawn(path, args, env)
  local start, ready = mtev.uuid(), mtev.uuid()
  if proc ~= nil then
    in_e:close()
    out_e:close()
    local dir = sourcedir(3)
    mtev.coroutine_spawn(function()
      local err_e = err_e:own()
      local started = false
      local outp = io.open(dir .. args[1] .. ".out",  "wb")
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
  local ok = mtev.waitfor(ready,1)
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
    local dir = sourcedir(3)
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
    local ok = mtev.waitfor(done,10)
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
