#!/bin/bash

set -e

cd $(dirname $0)

# Pass some arguments via the environment
LUA_COROS=10 \
LUA_WAIT=5 \
/opt/circonus/bin/luamtev -c hello-world.conf hello-world.lua
