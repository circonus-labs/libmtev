-- luamtev applications need to be wrapped in a module
module(...,package.seeall)

-- cache pid/tid
local pid, tid = mtev.thread_self()

-- initialize RNG
local s,us = mtev.gettimeofday()
math.randomseed(us)

function coro_main(coro_id, w)
  -- Q: Is there any way to get the identity of the currently running coroutine?
  --    like mtev.thread_self() just for co-routines?
  local wait = math.random(w)
  mtev.log("out","Hello from coro %d! waiting %d\n", coro_id, wait)

  -- suspend this co-routine. Yield to event loop.
  local slept = mtev.sleep(wait)
  mtev.notify("SLEEP", coro_id, slept:seconds())

  -- do some async I/O from the co-routine
  local proc = mtev.spawn("/bin/echo", { "echo", "Hello from echo" })
  local status, errno = proc:wait(1)
  mtev.notify("PROC", coro_id)
  -- Q: How can we communicate with the subprocess?
  --    - read from stdout/stderr
  --    - write to stdin

  -- TODO: Add HTTP GET example

  -- tell main() we are done
  mtev.notify("DONE", coro_id)
end

--
-- The main function is executed concurrently by all lua threads
-- when <concurrent>true</concurrent> is set in the config
--
-- Q: How to configure the threaded concurrency?
-- Apparently <default_queue_threads>10</default_queue_threads> in eventer/config is not doing it.
--
function main()
  -- Get parameters form the environment variables:
  -- Q: How to pass command line arguments to luamtev? ... is that possible at all?
  local N = tonumber(os.getenv("LUA_COROS")) or 10
  local WAIT = tonumber(os.getenv("LUA_WAIT")) or 5

  -- Say Hi!
  mtev.log("stdout", "Hello from thread %d/%d!\n", mtev.thread_self())
  mtev.log("stderr", "Hello to stderr\n")
  -- The "out"-log channel is configured to attach timestamps + debug info
  mtev.log("out", "Hi from debug channel!\n")

  -- Communicate between threads with shared state.
  local x = mtev.shared_get("X")
  if not x then
    -- this is a race condition here
    mtev.log("out", "setting X!\n")
    mtev.shared_set("X", "123")
  else
    mtev.log("out", "- found %s\n", x)
  end
  -- Discussion: Inter-thread communication seems to be pretty limited.
  -- For mtev.shared_set/get():
  -- - only string values are supported
  -- - no atomic operations "upsert" (mtev.shared_inc?)
  -- - no locking to avoid races (mtev.shared_lock()/shared_unlock()?)
  -- Q: Are there any other possibilities to communicate between threads?
  --    E.g. locks, semaphores, queues?

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
