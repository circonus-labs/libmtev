#!/bin/bash

if [ ! -d docs ]; then
	echo "No docs directory!"
	exit 2
fi

find docs -name \*.html -print -exec \
	perl -pi.foop -e 's/(gitbook.page.hasChanged.*)"mtime":"([^"]+)"/$1"mtime":""/g;' \
		-e 's/(gitbook.page.hasChanged.*)"time":"([^"]+)"/$1"time":""/g;' \
	{} \;

find docs -name \*.foop -exec rm {} \;
