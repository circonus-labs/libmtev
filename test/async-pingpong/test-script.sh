#!/bin/bash

RV=2

DIR=`dirname $0`
cd $DIR
./test -c ./test.conf >/dev/null 2>&1 &
sleep 0.2
OUT=`curl -s http://127.0.0.1:8888/test`
echo "$OUT"
kill -9 %1

exit 0
