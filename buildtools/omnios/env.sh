GCCPATH="/opt/gcc-4.8.1/bin"
export PATH="$GCCPATH:/opt/OMNIperl/bin:/opt/circonus/bin:/usr/gnu/bin:/usr/ccs/bin:/usr/bin:/usr/sbin:/usr/sfw/bin:/opt/onbld/bin/i386:/opt/circonus/bin/amd64:/opt/omni/bin:/opt/sunstudio12.1/bin"

export CFLAGS="-m64"
export CPPFLAGS="-I/opt/circonus/include/amd64 -I/opt/circonus/include -I/opt/circonus/include/amd64/luajit"
export LDFLAGS="-m64 -L/opt/circonus/lib/amd64 -R/opt/circonus/lib/amd64"
export MAKE=gmake

env
