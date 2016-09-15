#!/bin/bash

if [[ -n "$_DYLD_LIBRARY_PATH" ]]; then
	DYLD_LIBRARY_PATH=$_DYLD_LIBRARY_PATH
	export DYLD_LIBRARY_PATH
fi

rv=0
for cmd in $@; do
	if [[ "$VERBOSE" == "1" ]]; then
		./$cmd
	else
		./$cmd >/dev/null 2>/dev/null
	fi
	STATUS=$?
	RESULT="    #ok"
	if [[ "$STATUS" != "0" ]]; then
		rv=$STATUS
		RESULT="#NOT#ok"
	fi
	printf "%-50s %s.\n" "$cmd#" "$RESULT" | \
		sed -e 's/ /./g;' | sed -e 's/#/ /g;'
done

exit $rv

