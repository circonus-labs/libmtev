local print = print
local mtev = mtev

module('luatest')

function onethread()
  print("Hello World!")
end

function eachthread()
  local tid, id = mtev.thread_self()
  print("Hello World, I'm eventer: " .. id)
end
