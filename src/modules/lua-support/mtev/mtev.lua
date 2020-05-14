--
-- More functions under mtev.*
--

--/*!
--\lua time = mtev.time()
--\return the seconds since epoch (1970 UTC) as float
--*/
function _G.mtev.time()
  local sec, usec = mtev.gettimeofday()
  return sec + usec / 1000000
end

local function mk_reader_coro(fd)
  local key_done = "reader-coro-" .. mtev.uuid()
  mtev.coroutine_spawn(function()
      local fd = fd:own()
      local output = {}
      while true do
        local line = fd:read("\n")
        if not line then break end
        table.insert(output, line)
      end
      mtev.notify(key_done, table.concat(output))
      fd:close()
  end)
  return key_done
end

--/*!
--\lua status, stdout, stderr = mtev.exec(path, argv, env, timeout)
--\brief Spawn process return output on stdout, stderr as strings
--\return status is nil if a timeout was hit, stdout, stderr contain process output
--*/
function _G.mtev.exec(path, argv, env, timeout)
  assert(path)
  argv = argv or { path }
  env = env or { unpack(ENV) }

  -- env is an *ARRAY of key=value* not a table... but people always mess that up
  local needs_conversion = false
  local i = 1
  for _ in pairs(env) do
    if env[i] == nil then
      needs_conversion = true
      break
    end
    i = i + 1
  end
  if needs_conversion then
    local newenv = {}
    for k,v in pairs(env) do table.insert(newenv, k .. "=" .. tostring(v)) end
    env = newenv
  end

  timeout = timeout or 5
  local proc, in_e, out_e, err_e = mtev.spawn(path, argv, env)
  if not proc then error("cannot start proc") end
  in_e:close()
  local key_out = mk_reader_coro(out_e)
  local key_err = mk_reader_coro(err_e)
  local _, data_out = mtev.waitfor(key_out, timeout)
  local _, data_err = mtev.waitfor(key_err, timeout)
  local ret = proc:wait(timeout)
  if not ret then
    proc:kill() -- SIGTERM
    local ret = proc:wait(3)
    if not ret then
      proc:kill(9) -- SIGKILL
      local ret = proc:wait(3)
      if not ret then
        error("Couldn't kill process")
      end
    end
  end
  return ret, data_out, data_err
end

--/*!
--\lua status, stdout, stderr = mtev.sh(command, [timeout], [shell])
--\brief Run shell command, return output
--\param command to run
--\param timeout defaults to nil (infinite wait)
--\param shell which shell to use, defaults to $SHELL then to "/bin/sh"
--*/
function _G.mtev.sh(command, timeout, shell)
  shell = shell or ENV.SHELL or "/bin/sh"
  return mtev.exec(shell, { shell, "-c", command }, ENV, timeout)
end
