#!/bin/bash

RV=2

DIR=`dirname $0`
cd $DIR
exec ./test -c ./test.conf >/dev/null 2>&1
