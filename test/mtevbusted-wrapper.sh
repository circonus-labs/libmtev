#!/bin/sh

if [ "`uname`" = "SunOS" ] ; then
	LD_PRELOAD_64=$_LD_PRELOAD
	export LD_PRELOAD_64
else
	LD_PRELOAD=$_LD_PRELOAD
	export LD_PRELOAD
fi

exec ../src/luamtev \
    '-C../src/modules/mtev_lua/?.so;{package.cpath}'  \
    '-L../src/modules/lua-support/?.lua;./?.lua;./lua-harness/?.lua;{package.path}' \
    '-M../src/modules/' \
    ./mtevbusted-script -i lua-support/init.lua $@
