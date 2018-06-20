#!/bin/bash

set -e

cd "$(dirname $0)"

rm http.log || true

COROS=10
WAIT=5

/opt/circonus/bin/luamtev -c hello-world.conf hello-world.lua $COROS $WAIT
