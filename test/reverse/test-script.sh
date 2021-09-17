#!/bin/bash

exit $0
RV=2

DIR=`dirname $0`
cd $DIR
./test -c ./server.conf -s >/dev/null 2>&1 &
./test -c ./test.conf >/dev/null 2>&1 &

kill -9 %1
exit $RV
