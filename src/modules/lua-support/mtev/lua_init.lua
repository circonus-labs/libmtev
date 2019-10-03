--
-- Loaded during lua state initialization in mtev_lua_open()
--
-- Note: Do not rename this file to mtev/init.lua since it
-- might shadow mtev.so in the LUA_CPATH
--

mtev.timeval = require("mtev.timeval")

mtev.extras = require("mtev.extras")

mtev.Api = require("mtev.Api")

mtev.Proc = require("mtev.Proc")

require("mtev.mtev")

--
-- Global Helper Functions
--

function errorf(...) error(string.format(...)) end

function printf(...) print(string.format(...)) end

ffi = require("ffi")
ffi.cdef([=[
struct __mtev_console_closure { void *opaque; };
void nc_printf(struct __mtev_console_closure *ncct, const char *fmt, ...);
]=])
mtev.nc_printf = ffi.C.nc_printf
