local print = print

module('luatest')

function onethread()
  print("Hello World!\n")
end

function eachthread()
  print("Hello World!\n")
end
