#!/bin/bash -x

export PATH=/opt/circonus/bin:/opt/circonus/java/bin:/opt/circonus/bin:/opt/omni/bin:/usr/bin:/usr/sbin:/bin:/sbin:/usr/gnu/bin
export LDFLAGS='-m64 -Wl,-L/opt/circonus/lib -Wl,-rpath=/opt/circonus/lib -Wl,--enable-new-dtags'
export CFLAGS=-m64
export CFLAGSEXTRAS='-g -O2 -fno-strict-aliasing'
export CPPFLAGS='-I/opt/circonus/include -I/opt/circonus/include/luajit'
make $@
EXIT_CODE="$?"
if [ "$EXIT_CODE" != "0" ] ; then
  echo "*********************"
  echo "*** Build failed! ***"
  echo "*********************"
else
  echo "Successfully completed incremental build."
fi

exit $EXIT_CODE
