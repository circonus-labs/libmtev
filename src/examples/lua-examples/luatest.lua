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
end

