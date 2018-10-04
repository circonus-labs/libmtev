local _G = _G
local print = print
local pairs = pairs
local mtev = mtev
local nthreads = mtev.eventer_loop_concurrency()
local require = require

module('luatest')

function job(space, tid)
  mtev.log("error", "Job '%s' running in thread %d\n", space, tid)
end
function onethread()
  local thread, tid = mtev.thread_self()
  job("MAIN", tid)
end

function eachthread()
  local thread, tid = mtev.thread_self()
  job("THREAD", tid)
  mtev.hook("http_post_request", "mtev.hooks.http", "disable_compression")

  local appns = mtev.stats:ns("local"):ns("app")
  local hist = appns:register("lat", mtev.stats.HISTOGRAM)
  local text = appns:register("version", mtev.stats.STRING)
  local i32 = appns:register("i32", mtev.stats.INT32)
  local u64 = appns:register("u64", mtev.stats.UINT64)
  repeat
    local time = mtev.sleep(0.01)
    hist:record({12, -2})
    hist:record(1.3, 5)
    hist:record(time.sec + time.usec/1000000)
    text:record("  1234")
    i32:record(mtev.timeval.now().sec)
    u64:record(time.usec)
    mtev.log("error", "This is a dedup test\n")
  until false
end

