#!/bin/bash

RV=2

DIR=`dirname $0`
cd $DIR
./test -c ./test.conf >/dev/null 2>&1 &
LOOP=5
while [ $RV == 2 -a $LOOP -gt 0 ]; do
	OUT=`curl -s http://127.0.0.1:8888/test`
	if [[ "$OUT" == "Hello world" ]]; then
		RV=0
	else
		sleep 1
	fi
	LOOP=$(($LOOP - 1))
done
kill -9 %1

if [ $RV -eq 2 ]; then
	echo "Bad output $OUT"
fi
exit $RV
