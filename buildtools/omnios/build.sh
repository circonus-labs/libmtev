#!/bin/bash

DIR=$(dirname $0);

source $DIR/env.sh

$DIR/configure.sh

$DIR/make.sh
