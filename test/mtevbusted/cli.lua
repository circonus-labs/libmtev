local options = {}

function cli_option(flag, detail)
  options[flag] = detail
end

local argco = coroutine.create(function()
  for i, opt in ipairs(arg) do coroutine.yield(opt) end
end)

function nextarg()
  local co, arg = coroutine.resume(argco)
  return arg
end

function parsecli()
  nextarg() -- ignore the command
  local current_opt = nil
  while true do
    local opt = nextarg()
    if opt == nil then break end
    if opt:match("^-") then
      current_opt = opt:sub(2)
      if options[current_opt] == nil then
        usage("no such flag " .. current_opt)
      elseif type(options[current_opt].value) == "function" then
        local val = nextarg()
        if val == nil then usage(current_opt .. " requires argument") end
        options[current_opt].value(val)
      elseif type(options[current_opt].value) == "boolean" then
        options[current_opt].value = not options[current_opt].value
      else
        local val = nextarg()
        if val == nil then usage(current_opt .. " requires argument") end
        options[current_opt].value = val;
      end
    else
      break
    end
  end
  return options
end

function usage(err)
  mtev.log("error", "%s\n", arg[1])
  for flag, desc in pairs(options) do
    local def = ""
    if desc.default ~= nil and type(desc.default) ~= "function" then
      def = " [default: " .. tostring(desc.default) .. "]"
    end
    local param = (type(desc.value) == "boolean" and "" or " <arg>")
    mtev.log("error", "\t-%-20s%s%s\n", flag .. param, desc.help, def)
  end
  if err ~= nil then
    mtev.log("error", "\n\n\tError: %s\n", err)
  end
  os.exit(2)
end
