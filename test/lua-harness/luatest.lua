local _G = _G
local __buf = ''
local ffi = require('ffi')
local io = io
local os = require('os')
local print = print
local pairs = pairs
local filename = os.getenv('JUNIT_OUTPUT_FILE') or 'test_detail.xml'
local previowrite = io.write
local mteviowrite = function(s)
  __buf = __buf .. s
end
ffi.cdef([=[
  void exit(int);
]=])
local start_buffer = function()
  io.write = mteviowrite
end
local end_buffer = function()
  io.write = previowrite
  local copy = __buf
  __buf = ''
  return copy
end
local mtev = mtev
local nthreads = mtev.eventer_loop_concurrency()
local require = require
local pcall = pcall

local k,l,_=pcall(require,"luarocks.loader") _=k and l.add_context("busted","2.0.rc12-1")

local busted = require('busted.core')();
local filterLoader = require 'busted.modules.filter_loader'()
local helperLoader = require 'busted.modules.helper_loader'()
local outputHandlerLoader = require 'busted.modules.output_handler_loader'()
local luacov = require 'busted.modules.luacov'()
require 'busted'(busted)

outputHandlerLoader(
  busted, 'junit',
  { arguments = { filename }, language = 'en' }
)
outputHandlerLoader(
  busted, 'gtest',
  { language = 'en' }
)
helperLoader(busted, 'lua-support/mtev_load.lua', { verbose = true, language = 'lua' })

local testFileLoader = require 'busted.modules.test_file_loader'(busted, { 'lua', 'moonscript' })
testFileLoader({ '.' }, { '_spec' }, { recursive = true, excludes = {} })

module('luatest')

local function jobwatch()
  local todo = { }
  local fail = 0
  while true do
    local id, job, status, bad = mtev.waitfor('jobs', 1)
    if status == 'start' then
      todo[job] = 1
      fail = fail + bad
    end
    local cnt = 0
    for k,v in pairs(todo) do cnt = cnt + 1 end
    if cnt == 0 then
      mtev.log("test", "Jobs complete, failures: %d\n", fail)
      ffi.C.exit( fail == 0 and 0 or 2 )
    end
    if status == 'end' then
      todo[job] = nil
       fail = fail + bad
    end
  end
end
local tid, id = mtev.thread_self()
if id == 0 then
  mtev.coroutine_spawn(jobwatch)
end

function onethread()
  testsuite("MAIN")
end

function eachthread()
  --testsuite("THREAD")
end

function testsuite(context)
  local thread, tid = mtev.thread_self()
  local name = "testsuite-tid-" .. tid
  mtev.notify('jobs', name, 'start', 0)
  local failures = 0
  local errors = 0

  busted.subscribe({ 'error' }, function(...)
    errors = errors + 1
    return nil, true
  end)

  busted.subscribe({ 'test', 'end' }, function(...)
    if status == 'failure' then
      failures = failures + 1
    end
    return nil, true
  end)

  busted.subscribe({ 'suite', 'end' }, function (root, i, runs)
    local exit = 0
    if failures > 0 or errors > 0 then
      exit = 1
    end
    if context == "MAIN" then
      mtev.log("test", "%s testsuite finished\n", context)
    else
      mtev.log("test", "%s testsuite [%d/%d] finished\n", context, tid+1, nthreads)
    end
  end)

  busted.subscribe({ 'exit' }, function(...)
    mtev.log("test", "\n%s", end_buffer())
    mtev.notify('jobs', name, 'end', failures + errors)
  end)

  local execute = require 'busted.execute'(busted)
  start_buffer()
  execute(1, {
    seed = mtev.gettimeofday(),
    shuffle = true,
    sort = true,
  })
  busted.publish({ 'exit' })
end
