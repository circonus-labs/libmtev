-- luamtev applications need to be wrapped in a module
module(...,package.seeall)

local HttpClient = require('mtev.HttpClient')

-- Seed the random number generator
local s,us = mtev.gettimeofday()
math.randomseed(us)

--
-- The main function is executed concurrently by all lua threads
-- when <concurrent>true</concurrent> is set in the config
--
-- Q: How to configure the threaded concurrency?
-- Apparently <default_queue_threads>10</default_queue_threads> in eventer/config is not doing it.
--
function main()
  -- Read-in command line arguments
  local N = tonumber(arg[2]) or 10
  local WAIT = tonumber(arg[3]) or 5

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

  -- Q: Is there a way to list all co-routines within this lua state?

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
  -- We use a poor mans (racey) semaphore...
  local n_threads = mtev.eventer_loop_concurrency()
  mtev.log("out", "Waiting for %d threads to terminate\n", n_threads)
  mtev.shared_set("term", tostring((tonumber(mtev.shared_get("term")) or 0) + 1))
  mtev.log("out", "TERM: %s\n", mtev.shared_get("term"))
  while tonumber(mtev.shared_get("term")) < n_threads do
    mtev.sleep(.1)
  end

  -- Calling os.exit() terminates all threads.
  -- If we don't call os.exit() explicilty the process will keep running.
  -- Q: Is there a better way to "join lua threads and exit" ?
  --    Maybe:
  --    -> expose syncrhonization primitives, e.g. semaphores???
  --    -> Explicit config option to terminate process after main() has returned on all threads?
  --    -> Ignore the problem (concurrent one-shot applications might not common)
  mtev.log("out", "EXIT!\n")
  os.exit(0)
end

-- Main function of the coroutine
function coro_main(coro_id, w)
  local coro = coroutine.running()
  local wait = math.random(w)
  mtev.log("out","Hello from coro %d at %p. Waiting %ds\n", coro_id, coro, wait)

  -- suspend this co-routine. Yield to event loop.
  local slept = mtev.sleep(wait)
  mtev.notify("SLEEP", coro_id, slept:seconds())

  -- retrieve a global sequence number
  local n = mtev.shared_seq("key")
  mtev.log("out", "Global sequence %d.\n", coro_id, n)

  -- do some async I/O from the co-routine
  local proc = mtev.spawn("/bin/echo", { "echo", "Hello from echo" })
  local status, errno = proc:wait(1)
  mtev.notify("PROC", coro_id)
  -- It's also possible to communicate with the process via stdin/out/err
  -- See /test/mtevbusted/child.lua for examples.

  -- make an HTTP request
  local result = HTTP("google.com","/")
  mtev.log("http", "%s\n", result) -- This goes to http.log
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
