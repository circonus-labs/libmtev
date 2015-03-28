local _G = _G
local print = print
local mtev = mtev
local nthreads = mtev.eventer_loop_concurrency()
local require = require
local pcall = pcall

local busted = require('busted.core')();
local outputHandlerLoader = require 'busted.modules.output_handler_loader'()
require 'busted.init'(busted)
local outputHandlerOptions = {
  verbose = false,
  suppressPending = false,
  language = 'en',
  deferPrint = false
}
local outputHandler = outputHandlerLoader('plainTerminal', nil, outputHandlerOptions, busted)
outputHandler:subscribe(outputHandlerOptions)

local testFileLoader = require 'busted.modules.test_file_loader'(busted, { 'lua' })
testFileLoader('.', 'spec')

module('luatest')

function onethread()
  print("Hello World!")
end

function eachthread()
  local tid, id = mtev.thread_self()
  print("Hello World, I'm eventer: " .. id)
end

function testsuite()
  local thread, tid = mtev.thread_self()
  local failures = 0
  local errors = 0

  busted.subscribe({ 'error' }, function(...)
    errors = errors + 1
    return nil, true
  end)

  busted.subscribe({ 'test', 'end' }, function(element, parent, status)
    if status == 'failure' then
      failures = failures + 1
    end
    return nil, true
  end)

  busted.publish({ 'suite', 'start' })
  busted.execute()
  busted.publish({ 'suite', 'end' })

  local exit = 0
  if failures > 0 or errors > 0 then
    exit = 1
  end
  mtev.log("error", "testsuite [%d/%d] finished\n", tid+1, nthreads)
end
