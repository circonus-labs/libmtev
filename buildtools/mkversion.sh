#!/bin/sh

STATUS=`git status 2>&1`
if [ $? -eq 0 ]; then
  echo "Building version info from git"
  HASH=`git show --format=%H | head -1`
  TSTAMP=`git show --format=%at | head -1`
  echo "    * version -> $HASH"
  SYM=`git name-rev $HASH | awk '{print $2;}' | sed -e 's/\^.*//'`
  TAG=`git describe --tags --exact-match 2>/dev/null`
  if [ -n "$TAG" ]; then
    SYM="tags/$TAG"
  elif [ -z "`echo $SYM | grep '^tags/'`" ]; then
    SYM="branches/$SYM"
  fi
  echo "    * symbolic -> $SYM"
  BRANCH=$SYM
  VSTR=`printf "$BRANCH" | sed -e 's#^tags/##;' | sed -e 's#^branches/##;'`
  VERSION="$HASH.$TSTAMP"
  if [ -n "`echo $STATUS | grep 'Changed but not updated'`" ]; then
    VERSION="$HASH.modified.$TSTAMP"
  fi
else
  BRANCH=exported
  echo "    * exported"
fi

if [ -r "$1" ]; then
  eval `cat mtev_version.h | awk '/^#define/ { print $2"="$3;}'`
  if [ "$MTEV_BRANCH" = "$BRANCH" -a "$MTEV_VERSION" = "$VERSION" ]; then
    echo "    * version unchanged"
    exit
  fi
fi

cat > $1 <<EOF
#ifndef MTEV_VERSION_H
#ifndef MTEV_BRANCH
#define MTEV_BRANCH "$BRANCH"
#endif
#ifndef MTEV_VERSION
#define MTEV_VERSION "$VERSION"
#endif

#include <stdio.h>
#include <mtev_str.h>

#if defined(MTEV_VERSION_IMPL)
const char *mtev_branch = "$BRANCH";
const char *mtev_git_hash = "$HASH";
const char *mtev_version = "$VSTR";
#elif defined(MTEV_VERSION_DECL)
extern const char *mtev_branch;
extern const char *mtev_git_hash;
extern const char *mtev_version;
#endif

static inline int mtev_build_version(char *buff, int len) {
  mtev_strlcpy(buff, "$VSTR.$VERSION", len);
  return strlen(buff);
}

#endif
EOF
