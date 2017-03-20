#!/bin/bash

RV=2

DIR=`dirname $0`
cd $DIR
./test -c ./test.conf >/dev/null 2>&1 &
sleep 1
OUT=`curl -s http://127.0.0.1:8888/test`
if [[ "$OUT" == "Hello world" ]]; then
	RV=0
else
	echo "Bad output $OUT"
fi
kill -9 %1

exit $RV
