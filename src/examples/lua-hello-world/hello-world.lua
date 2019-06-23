-- luamtev applications need to be wrapped in a module
module(...,package.seeall)

local HttpClient = require('mtev.HttpClient')

-- Seed the random number generator
local s,us = mtev.gettimeofday()
math.randomseed(us)

--
-- The threaded concurrency, can be configured in hello-world.conf
-- The main function is executed concurrently by all lua threads
-- when <concurrent>true</concurrent> is set in the config
--
function main()
  -- Read-in command line arguments
  local N = tonumber(arg[2]) or 3
  local WAIT = tonumber(arg[3]) or .1

  -- Say Hi!
  mtev.log("stdout", "Hello from thread %d/%d!\n", mtev.thread_self())
  mtev.log("stderr", "Hello to stderr\n")
  -- The "out"-log channel is configured to attach timestamps + debug info
  mtev.log("out", "Hi from debug channel!\n")

  -- Communicate between threads with shared state.
  -- Inter-thread communication is currently pretty limited. We only have mtev.shared_set/get()
  local x = mtev.shared_get("X")
  if not x then
    -- this is a race condition here
    mtev.log("out", "setting X!\n")
    mtev.shared_set("X", "123")
  else
    mtev.log("out", "- found %s\n", x)
  end

  -- Let's spawn some coroutines
  for i=1,N do
    mtev.coroutine_spawn(coro_main, i, WAIT)
  end

  -- Join co-routines
  local results = {}
  for i=1,N do
    local key, coro, w = mtev.waitfor("SLEEP")
    mtev.log("out", "coro-%d notified %s after %.6fs\n", coro, key, w)
  end
  for i=1,N do
    local key, coro = mtev.waitfor("PROC")
    mtev.log("out", "coro-%d notified %s\n", coro, key)
  end
  for i=1,N do
    local key, coro = mtev.waitfor("HTTP")
    mtev.log("out", "coro-%d notified %s\n", coro, key)
  end
  for i=1,N do
    local key, coro = mtev.waitfor("DONE")
    mtev.log("out", "coro-%d notified %s\n", coro, key)
  end

  -- Join threads
  -- Wait until all threads are at this line here, so that we can safely terminate the program.
  local n_threads = mtev.eventer_loop_concurrency()
  local join_sem = mtev.semaphore("1CB22459-D022-4597-9C41-9FE26675A133", -n_threads + 1)
  join_sem:release()
  mtev.log("out", "Waiting for %d threads to terminate\n", n_threads)
  while not join_sem:try_acquire() do
    mtev.sleep(.1)
  end
  mtev.log("out", "EXIT!\n")
  os.exit(0)
end

-- Main function of the coroutine
function coro_main(coro_id, w)
  local coro = coroutine.running()
  local wait = math.random() * w
  mtev.log("out","Hello from coro %d at %p. Waiting %ds\n", coro_id, coro, wait)

  -- suspend this co-routine. Yield to event loop.
  local slept = mtev.sleep(wait)
  mtev.notify("SLEEP", coro_id, slept:seconds())

  -- retrieve a global sequence number
  local cnt = 3
  repeat
    mtev.log("out", "Global sequence key1 from coro %d: %d.\n", coro_id, mtev.shared_seq("key1"))
    mtev.log("out", "Global sequence key2 from coro %d: %d.\n", coro_id, mtev.shared_seq("key2"))
    cnt = cnt - 1
  until cnt < 0

  -- do some async I/O from the co-routine
  local proc = mtev.spawn("/bin/echo", { "echo", "Hello from echo" })
  local status, errno = proc:wait(1)
  mtev.notify("PROC", coro_id)
  -- It's also possible to communicate with the process via stdin/out/err
  -- See /test/mtevbusted/child.lua for examples.

  -- make an HTTP request
  -- local result = HTTP("google.com","/")
  -- mtev.log("http", "%s\n", result) -- This goes to http.log
  mtev.notify("HTTP", coro_id)

  -- tell main() we are done
  mtev.notify("DONE", coro_id)
end

function HTTP(host, path)
  local port = 80
  local headers = {}
  local method = "GET"
  local ip
  local dns = mtev.dns()
  if not dns.is_valid_ip(host) then
    local r = dns:lookup(host)
    ip = r.a
  end

  local output_buf = {}
  local callbacks = {}
  callbacks.consume = function (str) output_buf[#output_buf+1] =  str end
  callbacks.headers = function (hdrs) in_headers = hdrs end

  local client = HttpClient:new(callbacks)
  local rv, err = client:connect(ip, port)
  if rv ~= 0 then error("Connection failed") end
  headers.Host = host
  headers.Accept = 'text/HTML'
  client:do_request(method, path, headers, nil, "1.1")
  client:get_response(100000000)
  return table.concat(output_buf)
end
