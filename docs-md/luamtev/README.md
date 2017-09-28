# luamtev

libmtev takes Lua seariously.  We're specific about supporting luajit and while
luajit is a very powerful runtime, we felt we'd get more power by exposing the luajit
runtime via a standalone libmtev application; luamtev was board.

luamtev is a non-interactive interpreter for luacode.  Unlike the normal luajit
interpreter, it only runs modules, but it first boots a comprehensive libmtev runtime
before and then runs the provided module within that runtime.  This allows use of
all of the advanced features of libmtev.

