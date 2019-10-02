#!/bin/bash

perl -ni -e 's/^(\S+)\.o:/$1.o $1.lo:/g; s/(\s)\/\S+/$1/g; s#\S+flatbuffers_common_\S+##g; next if /^\s*\\?$/; print "\n" if /^\S/; s/^\s+(?=\S)/  /g; print;' $*
