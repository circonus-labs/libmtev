# luamtev

libmtev takes Lua seriously.  We're specific about supporting LuaJIT and while
LuaJIT is a very powerful runtime, we felt we'd get more power by exposing the LuaJIT
runtime via a standalone libmtev application; luamtev was born.

luamtev is a non-interactive interpreter for luacode.  Unlike the normal LuaJIT
interpreter, it only runs modules, but it first boots a comprehensive libmtev runtime
and then runs the provided module within that runtime.  This allows use of
all of the advanced features of libmtev.

