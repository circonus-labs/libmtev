#!/bin/sh

exec ../src/luamtev \
    '-C../src/modules/mtev_lua/?.so;{package.cpath}'  \
    '-L../src/modules/lua-support/?.lua;./lua-harness/?.lua;{package.path}' \
    '-M../src/modules/' \
    ./mtevbusted-script -i lua-support/init.lua $@
