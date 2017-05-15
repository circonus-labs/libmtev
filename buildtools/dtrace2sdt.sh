#!/bin/bash

FILE=$1
TGT=$2

if [[ -n "$TGT" ]]; then
	exec 1>$TGT
fi
cat <<EOF
#ifndef AUTO_PROBE_$$
#define AUTO_PROBE_$$

#include <sys/sdt.h>

EOF

cat $FILE | egrep '^#define.*\(' | \
	sed -e 's/^#define[	 ]*//g; s/).*/)/g;' | \
	grep -v _ENABLED | sort | uniq | \
	awk '{
		match($0, "^([^_]+)", appname);
		match($0, "_([^\\(]+)", _func);
		match($0, "\\((.+)\\)", dargs);
		if(length(dargs[1]) == 0) {
			print "#define "appname[1]"_"_func[1]"_ENABLED() 1"
			print "#define "appname[1]"_"_func[1]"("dargs[1]") STAP_PROBE("tolower(appname[1])","tolower(_func[1])")"
		} else {
			cnt = substr(dargs[1], length(dargs[1])) + 1
			print "#define "appname[1]"_"_func[1]"_ENABLED() 1"
			print "#define "appname[1]"_"_func[1]"("dargs[1]") STAP_PROBE"cnt"("tolower(appname[1])","tolower(_func[1])","dargs[1]")"
		}
	}'

echo "#endif"
