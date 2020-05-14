#!/bin/bash

DIR=`dirname $0`
cd $DIR

if [ "`uname`" = "SunOS" ] ; then
	LD_PRELOAD_64=$_LD_PRELOAD
	export LD_PRELOAD_64
else
	LD_PRELOAD=$_LD_PRELOAD
	export LD_PRELOAD
fi

LUAMTEV="../../src/luamtev
    -C../../src/modules/mtev_lua/?.so;{package.cpath}
    -L../../src/modules/lua-support/?.lua;./?.lua;./lua-harness/?.lua;{package.path}
    -M../../src/modules/"

RV=0
check() {
  echo -n "$@ ... "
}
ok() {
  echo " ok"
}
bad() {
  echo "bad ($@)"
}

check "help"
OUT=$($LUAMTEV -h)
test $? -eq 0 -a -n "$OUT" && ok || bad $?

check "template"
OUT=$($LUAMTEV -T simple.lua > tmp.conf 2>&1)
test $? -eq 0 -a -z "$OUT" && ok || bad $OUT

check "use template"
OUT=$($LUAMTEV -c tmp.conf simple.lua)
test $? -eq 0 -a "$OUT" == "main" && ok || bad $OUT

rm -f tmp.conf

check "main"
OUT=$($LUAMTEV simple.lua)
test $? -eq 0 -a "$OUT" == "main" && ok || bad $OUT

check "alternate"
OUT=$($LUAMTEV -e alternate simple.lua)
test $? -eq 0 -a "$OUT" == "alternate" && ok || bad $OUT

check "interactive"
IN=$(cat<<EOF
show version
shutdown
EOF
)
OUT=$(echo "$IN" | $LUAMTEV -n 4 -e interactive -i simple.lua | grep build)
test $? -eq 0 -a -n "$OUT" && ok || bad $OUT

check "crash"
OUT=$(echo "crash" | $LUAMTEV -e interactive -i simple.lua 2>&1 | grep STACKTRACE)
test $? -eq 0 -a -n "$OUT" && ok || bad $OUT

exit $RV
