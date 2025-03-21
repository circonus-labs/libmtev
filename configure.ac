AC_INIT([libmtev], [], [] [https://github.com/circonus-labs/libmtev])

m4_include([buildtools/compile_flags.m4])

AH_TOP([
#ifndef MTEV_CONFIG_H
#define MTEV_CONFIG_H
])
AH_BOTTOM([#endif])

AC_CONFIG_SRCDIR([src/mtev_main.c])
AC_CONFIG_AUX_DIR(buildtools)

node=`hostname | cut -f1 -d '.' | tr '[A-Z]' '[a-z]'`
if test -f ".configure.$node"; then
	echo "***********************************************************"
	echo "* Loading node specific configure settings for $node."
	echo "***********************************************************"
	. ./.configure.$node
fi

AC_CANONICAL_HOST
AC_CONFIG_HEADER(src/mtev_config.h)

AC_ARG_ENABLE(coverage,
	[AC_HELP_STRING([--enable-coverage],
		[Compile with gcov support])],
	enable_coverage="$enableval",
	enable_coverage=no)

AC_ARG_ENABLE(strict,
	[AC_HELP_STRING([--disable-strict],
		[Compile with warnings treated as errors])],
	enable_strict="$enableval",
	enable_strict=yes)

AC_ARG_ENABLE(lua,
  [AC_HELP_STRING([--enable-lua],
    [Choose a Lua implementation: (no, LuaJIT)])],
  [ENABLE_LUA=`echo $enableval | tr A-Z a-z`],
  [ENABLE_LUA="luajit"])

AC_ARG_ENABLE(lmdb,
[AC_HELP_STRING([--disable-lmdb],
[Turn off LMDB dependence, mtev_huge_hash will not function])],
enable_lmdb="$enableval",
enable_lmdb=yes)

AS_CASE($ENABLE_LUA,
 [no], [],
 [yes], [ENABLE_LUA="luajit"],
 [luajit], [],
 [AC_MSG_ERROR([Invalid value '$ENABLE_LUA' for --enable-lua])]
)

AC_ARG_ENABLE(rdtsc,
	[AC_HELP_STRING([--enable-rdtsc],
		[Turn on usage of rdtsc for high res clock])],
	enable_rdtsc="$enableval",
	enable_rdtsc="$DEFAULT_ENABLE_RDTSC")

: ${CFLAGS="-g -O2 -fno-omit-frame-pointer"}
: ${CXXFLAGS="-g -O2 -fno-omit-frame-pointer"}

AC_PROG_CC
AX_CHECK_COMPILE_FLAG([-std=c11],
  [AX_APPEND_FLAG([-std=c11])],
  [AC_MSG_WARN([-std=c11 not supported, you may have to set CFLAGS to enable C11 support.])]
)

AC_PROG_CXX
AC_LANG_PUSH(C++)
AX_CHECK_COMPILE_FLAG([-std=c++20],
  [AX_APPEND_FLAG([-std=c++20])],
  [AC_MSG_WARN([-std=c++20 not supported, you may have to set CXXFLAGS to enable C++20 support.])]
)
AC_LANG_POP(C++)

AC_C_INLINE
AC_C_BIGENDIAN
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PATH_PROG(LCOV, lcov)
AC_PATH_PROG(GCOV, gcov)
AC_PATH_PROG(AR, ar)
AC_PATH_PROGS(PERL, perl)
AM_PATH_PYTHON()
AC_PATH_PROGS(XSLTPROC, xsltproc)
AC_PATH_PROGS(XMLLINT, xmllint)
AC_PATH_PROG(NROFF, nroff)
AC_PATH_PROG(CTFCONVERT, ctfconvert)
AC_PATH_PROG(CTFMERGE, ctfmerge)
AC_CHECK_PROG(FLATCC_CHECK,flatcc,yes)
if test x"$FLATCC_CHECK" != x"yes" ; then
  AC_MSG_ERROR([*** flatcc is required for building. ***])
else
  AC_PATH_PROG(FLATCC, flatcc)
fi
AC_PATH_PROG(LUA, luajit)
AC_PATH_PROG(LUAROCKS, luarocks)
if test -z "$ac_cv_path_LUA"; then
  AC_PATH_PROG(LUA, lua)
fi
AC_SUBST(PERL)

AC_ARG_ENABLE(luarocks-path,
  [AC_HELP_STRING([--enable-luarock-path],
    [Set a LUA_PATH to see luarocks: (no, LuaJIT)])],
  [LUAROCKS_PATH="$enableval"],
  [LUAROCKS_PATH=`$LUAROCKS path --lr-path | sed -e 's#[^;]*home[^;]*;##g;'`])
AC_MSG_CHECKING([luarocks LUA_PATH])
AC_MSG_RESULT([$LUAROCKS_PATH])
AC_SUBST(LUAROCKS_PATH)

if test "x$GCC" = "xyes" ; then
	# This is a dumb hack to detect clang vs. gcc to avoid -O5 warnings
	BARECC=`echo -n $CC | sed -e 's/ .*//;'`
	CLANG=`$BARECC -v 2>&1 | grep clang`
	if test -n "$CLANG"; then
		CHOTOPT="-O3"
	else
		CHOTOPT="-O5"
	fi
	DEPFLAGS="-MM"
fi

CPPFLAGS="$CPPFLAGS -D_REENTRANT "'-I$(top_srcdir)/src'
DTRACEHDR=libmtev_dtrace_probes.h
DTRACEHDR_TRANSFORM="copy"
DOTSO=.so
if test "x$BUILD_ASAN" = "x"; then
  TGT_NAME="libmtev"
  LD_LIBMTEV_VERSION='-Wl,-soname,libmtev.so.$(SEMVER_MAJOR)'
else
  TGT_NAME="libmtev-asan"
  LD_LIBMTEV_VERSION='-Wl,-soname,libmtev-asan.so.$(SEMVER_MAJOR)'
fi
MAPFLAGS=""
AKLOMPENV="AVX2_CFLAGS=-mavx2 SSSE3_CFLAGS=-mssse3 SSE41_CFLAGS=-msse4.1 SSE42_CFLAGS=-msse4.2 AVX_CFLAGS=-mavx"
DEFAULT_ENABLE_RDTSC=yes

case $host in
aarch64-*-*-*)
	AKLOMPENV="NEON32_CFLAGS=-march=armv8-a+simd NEON64_CFLAGS=-march=armv8-a+simd"
	DEFAULT_ENABLE_RDTSC=no
	;;
esac

case $host in
*-*-darwin*)
	CAP_PLATFORM="darwin"
	DOTSO=
	DOTDYLIB=dylib
	DTRACE=/usr/sbin/dtrace
	DTRACE_ENABLED=1
	PICFLAGS="-fPIC"
	CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE=600 -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE"
	CPPFLAGS="$CPPFLAGS -D_DARWIN_C_SOURCE -DMAC_OS_X_VERSION_MIN_REQUIRED=MAC_OS_X_VERSION_10_6 -Wno-deprecated-declarations"
	MODULELD="$CC -bundle -flat_namespace -undefined suppress"
	SHLD="$CC -dynamiclib -single_module -undefined dynamic_lookup -fPIC"
  DOTDYLIB=.dylib
	LD_LIBMTEV_VERSION='-current_version $(SEMVER_MAJOR) -install_name $(libdir)/libmtev.$(LIBMTEV_VERSION).dylib'
	MODULEEXT=bundle
	# This is needed for luajit on Mac OS X
	if test "x$ENABLE_LUA" = "xluajit"; then
		LDFLAGS="$LDFLAGS -pagezero_size 10000 -image_base 100000000"
		SHLDFLAGS="$SHLDFLAGS -image_base 100000000"
	fi
	;;
*-*-solaris*)
	# unless we explicitly say m32, we want m64
	if test -z "`echo $CFLAGS | grep m32`" ; then
		CFLAGS="-m64 $CFLAGS"
	fi
	if test -z "`echo $LDFLAGS | grep m32`" ; then
		LDFLAGS="-m64 $LDFLAGS"
	fi
	# Fix up default paths on 64-bit stuff.
	if test -n "`echo $CFLAGS | grep m64`" ; then
		if test "x$libdir" = 'x${exec_prefix}/lib' ; then
			libdir="\${exec_prefix}/lib/amd64"
		fi
		if test "x$libexecdir" = 'x${exec_prefix}/libexec' ; then
			libexecdir="\${exec_prefix}/libexec/amd64"
		fi
		if test "x$includedir" = 'x${prefix}/include' ; then
			includedir="\${prefix}/include/amd64"
		fi
	fi
	CAP_PLATFORM="illumos"
	CAP_SUPPORTED=1
	DTRACE=/usr/sbin/dtrace
	DTRACE_ENABLED=1
	DTRACEOBJ=dtrace_stub.o
	FAST_TIME_PRELOAD="mtev_time_fast.so"
	CFLAGS="$CFLAGS"
	CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE=600 -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE"
	CPPFLAGS="$CPPFLAGS -D__EXTENSIONS__"
	MDB_MODS="mdb-support/libmtev.so"
	if test "x$GCC" != "xyes" ; then
		AC_MSG_CHECKING([32 or 64 bit Solaris assembly])
		if test -n "`echo $CFLAGS | grep m64`" ; then
			DTRACEFLAGS="-64 -Z"
			CPPFLAGS="-I/usr/include/amd64 $CPPFLAGS -I$prefix/include/amd64/luajit -I$prefix/include"
			MAPFLAGS="-Wl,-M -Wl,map64bit"
			if test -n "`isalist | grep sparc`"; then
				AC_MSG_RESULT([sparc 64])
				ATOMIC_OBJS="mtev_atomic_sol_sparcv9.lo"
			else
				AC_MSG_RESULT([intel 64])
				ATOMIC_OBJS="mtev_atomic_sol_x86_64.lo"
			fi
		else
			if test -n "`isalist | grep sparc`"; then
				AC_MSG_RESULT([sparc 32])
				ATOMIC_OBJS="mtev_atomic_sol_sparcv8plus.lo"
			else
				AC_MSG_RESULT([intel 32])
				ATOMIC_OBJS="mtev_atomic_sol_x86_32.lo"
			fi
		fi
	else
		UNWINDLIB=-lgcc_s
	fi
	if test "x$GCC" != "xyes" ; then
		CFLAGS="$CFLAGS -mt"
		PICFLAGS="-Kpic"
		MODULELD="$CC -G"
		SHLD="$CC -G"
	else
		if test -n "`echo $CFLAGS | grep m64`" ; then
			CPPFLAGS="-I/usr/include/amd64 $CPPFLAGS -I$prefix/include/amd64/luajit -I$prefix/include"
			DTRACEFLAGS="-64 -Z"
			MAPFLAGS="-Wl,-M -Wl,map64bit"
		fi
		PICFLAGS="-fPIC"
		MODULELD="$CC -shared"
		SHLD="$CC -shared"
		CLINKFLAGS="-shared-libgcc"
	fi
	MODULEEXT=so
	RLDFLAG="-R"
	WHOLE_ARCHIVE="-Wl,-z -Wl,allextract"
	NOWHOLE_ARCHIVE="-Wl,-z -Wl,defaultextract"
	;;
*-*-openbsd*)
	CAP_PLATFORM="openbsd"
	PICFLAGS="-fpic"
	LDFLAGS="$LDFLAGS -Wl,-E"
	MODULELD="$CC -shared"
	SHLD="$CC -shared"
	MODULEEXT=so
	LDFLAGS="$LDFLAGS -L/usr/local/lib"
	CFLAGS="$CFLAGS -I/usr/local/include"
	RLDFLAG="-Wl,--enable-new-dtags -Wl,--rpath="
	WHOLE_ARCHIVE="-Wl,--whole-archive"
	NOWHOLE_ARCHIVE="-Wl,--no-whole-archive"
	;;
*-*-linux*)
	CAP_PLATFORM="linux"
	DTRACEHDR_TRANSFORM="sdt"
	if test -x /usr/bin/dtrace ; then
		# System tap has a header-producing doppelganger
		DTRACE=/usr/bin/dtrace
		DTRACEOBJ=dtrace_stub.o
	fi
	LDFLAGS="$LDFLAGS -Wl,-E"
	CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE=600 -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE"
	CPPFLAGS="$CPPFLAGS -D_SVID_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE"
	PICFLAGS="-fpic"
	MODULELD="$CC -shared"
	SHLD="$CC -shared"
	MODULEEXT=so
	RLDFLAG="-Wl,--enable-new-dtags -Wl,--rpath="
	WHOLE_ARCHIVE="-Wl,--whole-archive"
	NOWHOLE_ARCHIVE="-Wl,--no-whole-archive"
	;;
*-*-freebsd*)
	CAP_PLATFORM="freebsd"
	PICFLAGS="-fpic"
	MODULELD="$CC -shared"
	SHLD="$CC -shared"
	LDFLAGS="$LDFLAGS -Wl,--export-dynamic -L/usr/local/lib"
	CFLAGS="$CFLAGS -DCOMPAT_43TTY -I/usr/local/include"
	MODULEEXT=so
	RLDFLAG="-Wl,--enable-new-dtags -Wl,--rpath="
	;;
*)
	PICFLAGS="-fpic"
	MODULELD="$CC -shared"
	MODULEEXT=so
	RLDFLAG="-Wl,--enable-new-dtags -Wl,--rpath="
	;;
esac

# Force resolve all the paths
SUBPREFIX="$prefix"
if test "x$prefix" = "xNONE"; then
	SUBPREFIX="$ac_default_prefix"
fi
AC_MSG_CHECKING([Resolving libexec path...])
fullpath=$libexecdir
while test "x$temppath" != "x$fullpath" ; do
	temppath=$fullpath
	fullpath=`eval echo ${fullpath}`
done
fullpath=`echo $fullpath | sed "s~NONE~$SUBPREFIX~"`
AC_MSG_RESULT([$fullpath/mtev])
AC_DEFINE_UNQUOTED(MTEV_MODULES_DIR, "${fullpath}/mtev", [modules dir])
MODULES_DIR=${fullpath}/mtev
AC_SUBST(MODULES_DIR)

AC_MSG_CHECKING([Resolving bindir path...])
fullpath=$bindir
while test "x$temppath" != "x$fullpath" ; do
	temppath=$fullpath
	fullpath=`eval echo ${fullpath}`
done
fullpath=`echo $fullpath | sed "s~NONE~$SUBPREFIX~"`
bindir=${fullpath}
AC_MSG_RESULT([$fullpath])

AC_MSG_CHECKING([Resolving lib path...])
fullpath=$libdir
while test "x$temppath" != "x$fullpath" ; do
	temppath=$fullpath
	fullpath=`eval echo ${fullpath}`
done
fullpath=`echo $fullpath | sed "s~NONE~$SUBPREFIX~"`
AC_MSG_RESULT([$fullpath])
AC_DEFINE_UNQUOTED(MTEV_LIB_DIR, "${fullpath}", [lib dir])
LIB_DIR=${fullpath}

AC_MSG_CHECKING([Resolving include path...])
fullpath=$includedir
while test "x$temppath" != "x$fullpath" ; do
	temppath=$fullpath
	fullpath=`eval echo ${fullpath}`
done
fullpath=`echo $fullpath | sed "s~NONE~$SUBPREFIX~"`
AC_MSG_RESULT([$fullpath])
INCLUDE_DIR=${fullpath}

AC_MSG_CHECKING([Resolving sysconfdir path...])
fullpath=$sysconfdir
while test "x$temppath" != "x$fullpath" ; do
	temppath=$fullpath
	fullpath=`eval echo ${fullpath}`
done
fullpath=`echo $fullpath | sed "s~NONE~$SUBPREFIX~"`
AC_MSG_RESULT([$fullpath])
AC_DEFINE_UNQUOTED(MTEV_ETC_DIR, "${fullpath}", [etc dir])
ETC_DIR=${fullpath}
AC_SUBST(ETC_DIR)

CPPFLAGS="-I$INCLUDE_DIR $CPPFLAGS"
LD="$CXX"
LDFLAGS="$LDFLAGS -L$LIB_DIR $RLDFLAG$LIB_DIR"
SHLDFLAGS="$LDFLAGS"

AC_SUBST(CHOTOPT)
AC_SUBST(DOTSO)
AC_SUBST(DOTDYLIB)
AC_SUBST(LD_LIBMTEV_VERSION)
AC_SUBST(MDB_MODS)
AC_SUBST(FAST_TIME_PRELOAD)
AC_SUBST(TGT_NAME)

AC_DEFINE_UNQUOTED(CAP_PLATFORM, "$CAP_PLATFORM", [Capabilities platform.])
AS_IF([test "x$CAP_SUPPORTED" = "x1"],
    [ AC_DEFINE(CAP_SUPPORTED, [1], [Capabilities are supported.]) ],
)

AC_SUBST(DTRACE)
AC_SUBST(DTRACE_ENABLED)
AS_IF([test "x$DTRACE_ENABLED" = "x1"],
    [ AC_DEFINE(DTRACE_ENABLED, [1], [DTrace enabled.]) ]
)

## If there's no sys/sdt.h, set the DTRACEHDR_TRANSFORM back to copy
AC_CHECK_HEADER(sys/sdt.h, [], [ DTRACEHDR_TRANSFORM="copy" ])

AC_SUBST(DTRACEOBJ)
AC_SUBST(DTRACEHDR)
AC_SUBST(DTRACEHDR_TRANSFORM)
AC_SUBST(DTRACEFLAGS)
AC_SUBST(MAPFLAGS)
AC_SUBST(CLINKFLAGS)
AC_SUBST(AKLOMPENV)
AC_SUBST(SHLD)
AC_SUBST(RLDFLAG)
AC_SUBST(DEPFLAGS)
AC_SUBST(MODULELD)
AC_SUBST(MODULEEXT)
AC_SUBST(WHOLE_ARCHIVE)
AC_SUBST(NOWHOLE_ARCHIVE)
AC_SUBST(ATOMIC_OBJS)
AC_SUBST(UNWINDLIB)
AC_DEFINE_UNQUOTED(MODULEEXT, "$MODULEEXT", [module extension])

AS_IF([test x"$enable_rdtsc" = x"yes"],
    [ AC_DEFINE(ENABLE_RDTSC, [1], [RDTSC enabled]) ]
)

# Checks for data types
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(long long int, 8)
AC_CHECK_SIZEOF(void *, 1)

AC_CHECK_HEADERS(libdwarf/libdwarf.h)
AC_CHECK_LIB(dwarf, dwarf_init, , )
AC_CHECK_LIB(unwind, unw_backtrace, , )
AC_CHECK_HEADER(ck_pr.h, [], [AC_MSG_ERROR([*** libck (headers) required ***])])
AC_CHECK_LIB(ck, ck_ht_init, , [AC_MSG_ERROR([*** concurrencyckit (libck) is required ***])])
AC_CHECK_FUNCS(ck_epoch_synchronize_wait)
AC_CHECK_LIB(hwloc, hwloc_topology_init, , [AC_MSG_ERROR([*** libhwloc required ***])])
AC_CHECK_HEADER(lz4.h, [], [AC_MSG_ERROR([*** liblz4 (headers) required ***])])
AC_CHECK_LIB(lz4, LZ4F_compressBegin, , [AC_MSG_ERROR([*** liblz4 is required ***])])
AC_CHECK_LIB(flatccrt, flatcc_builder_aligned_free, , [AC_MSG_ERROR([*** libflatcc 0.4.3* or higher is required ***])])
AC_CHECK_LIB(yajl, yajl_alloc, , [AC_MSG_ERROR(*** libyajl is required ***)])
AC_CHECK_HEADER(curl/curl.h, [], [AC_MSG_ERROR([*** libcurl headers required ***])])
AC_CHECK_LIB(curl, curl_global_init, [], [AC_MSG_ERROR([*** libcurl required ***])])

# libcircmetrics depends on libjlog and libcircllhist, so we have to check
# for them in reverse dependency order so that $LIBS contains the correct
# dependencies at each step.
AC_CHECK_LIB(dl, dlsym, , )
AC_CHECK_LIB(m, exp, , )
AC_CHECK_LIB(jlog, jlog_new, , [AC_MSG_ERROR([*** libjlog required github.com/omniti-labs/jlog ***])])
AC_CHECK_LIB(circllhist, hist_insert, , [AC_MSG_ERROR([*** libcircllhist is required ***])])
AC_CHECK_LIB(circmetrics, stats_recorder_alloc, , [AC_MSG_ERROR([*** libcircmetrics is required ***])])

AC_CHECK_LIB(umem, umem_cache_create, [
	LIBS="$LIBS -lumem"
	AC_DEFINE(HAVE_LIBUMEM, [1], [have libumem])
], )
AC_CHECK_LIB(z, compress2, , [AC_MSG_ERROR([*** zlib is required ***])])
AC_CHECK_LIB(rt, sem_init, , [
  AC_CHECK_LIB(rt, clock_gettime, , )
])
AC_CHECK_LIB(posix4, sem_wait, , )
AC_CHECK_LIB(pthread, pthread_create, , )
AC_CHECK_LIB(execinfo, backtrace, , )

AC_CHECK_FUNC(pthread_setname_np, AC_DEFINE(HAVE_PTHREAD_SETNAME_NP, [1], [pthread_setname_np]))
AC_CHECK_FUNC(pthread_set_name_np, AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP, [1], [pthread_set_name_np]))
AC_CHECK_FUNC(pthread_rwlockattr_setkind_np, AC_DEFINE(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP, [1], [pthread_rwlockattr_setkind_np]))

# Check for LuaJIT
OLD_LIBS=$LIBS
LIBS=

AS_IF([test "x$ENABLE_LUA" = "xluajit"], [

    # Find the LuaJIT headers from pkg-config. Otherwise
    # we risk accidentally building against Lua 5.x headers
    # that might be in our default search path.
    AC_MSG_CHECKING([LuaJIT CFLAGS])
    LUAJIT_CFLAGS=`pkg-config --cflags luajit 2>/dev/null`

    AC_CHECK_HEADER(lj_obj.h, [AC_DEFINE(HAVE_LUAJIT_SOURCE, [1], [have luajit sources])], [AC_MSG_WARN([*** no libluajit source build in include path ***])])
    CFLAGS="$CFLAGS $LUAJIT_CFLAGS"
    CXXFLAGS="$CXXFLAGS $LUAJIT_CFLAGS"
    AC_MSG_RESULT([checking luajit CFLAGS: $LUAJIT_CFLAGS])

    AC_CHECK_LIB(rt, timer_create)
    AC_CHECK_LIB(pthread, pthread_getspecific)
    AC_CHECK_LIB(circmetrics, stats_handle_alloc)
    AC_CHECK_LIB(luajit-5.1, luaL_newstate, [],
                    [AC_MSG_ERROR([*** libluajit-5.1 required ***])])

    AC_CHECK_HEADER(lua.h, [], [AC_MSG_ERROR([*** lua (headers) required ***])])
    AC_CHECK_HEADER(udns.h, [], [AC_MSG_ERROR([*** udns.h required ***])])
    AC_CHECK_LIB(udns, dns_new, [], [AC_MSG_ERROR([*** libudns required ***])])

    LUA_LUAMTEV=luamtev
    # This is the lua module for mtev.  libmtev <generic> stanza loads this.
    LUA_MODULES=lua_mtev.$MODULEEXT
])

LUALIBS="$LUALIBS $LIBS"
AC_SUBST(LUALIBS)
AC_SUBST(LUA_LUAMTEV)
LIBS=$OLD_LIBS

AC_ARG_ENABLE([zipkin_fq],
    AS_HELP_STRING([--disable-zipkin-fq], [Disable modules zipkin-fq]),
    [],
    [enable_zipkin_fq=check])

ZIPKIN_FQ_BUILT="no"
AS_IF([test "x$enable_zipkin_fq" != "xno"], [
    OLD_LIBS=$LIBS
    LIBS=
    AC_CHECK_LIB(fq, fq_client_init,
        [FQ_MODULES="$FQ_MODULES zipkin_fq.$MODULEEXT"
         ZIPKIN_FQ_BUILT="yes"],
        [if test "x$enable_zipkin_fq" == "xcheck"; then
            AC_MSG_NOTICE([NOTICE: not building zipkin-fq module, no fq library found])
            ZIPKIN_FQ_BUILT="no"
         else
            AC_MSG_ERROR([*** can't build zipkin-fq, no -lfq ***])
         fi
        ]
    )
    LIBS=$OLD_LIBS
])

AC_ARG_ENABLE([fq],
    AS_HELP_STRING([--disable-fq], [Disable modules fq]),
    [],
    [enable_fq=check])

FQ_BUILT="no"
AS_IF([test "x$enable_fq" != "xno"], [
    OLD_LIBS=$LIBS
    LIBS=
    AC_CHECK_LIB(fq, fq_client_init,
        [FQ_MODULES="$FQ_MODULES fq.$MODULEEXT"
         EXTRA_EXAMPLES="$EXTRA_EXAMPLES fq-router"
         FQ_BUILT="yes"],
        [if test "x$enable_fq" == "xcheck"; then
            AC_MSG_NOTICE([NOTICE: not building fq module, no fq library found])
            FQ_BUILT="no"
         else
            AC_MSG_ERROR([*** can't build fq, no -lfq ***])
         fi
        ]
    )
    LIBS=$OLD_LIBS
])

AC_ARG_ENABLE([kafka],
    AS_HELP_STRING([--disable-kafka], [Disable modules kafka]),
    [],
    [enable_kafka=check])

KAFKA_BUILT="no"
AS_IF([test "x$enable_kafka" != "xno"], [
    OLD_LIBS=$LIBS
    LIBS=
    AC_CHECK_LIB(rdkafka, rd_kafka_conf_new,
        [KAFKA_MODULES="$KAFKA_MODULES kafka.$MODULEEXT"
         KAFKA_BUILT="yes"],
        [if test "x$enable_kafka" == "xcheck"; then
            AC_MSG_NOTICE([NOTICE: not building kafka module, no kafka library found])
            KAFKA_BUILT="no"
         else
            AC_MSG_ERROR([*** can't build kafka, no -lrdkafka ***])
         fi
        ]
    )
    LIBS=$OLD_LIBS
])

AC_ARG_ENABLE([amqp],
    AS_HELP_STRING([--disable-amqp], [Disable modules amqp]),
    [],
    [enable_amqp=check])

AMQP_BUILT="no"
AS_IF([test "x$enable_amqp" != "xno"], [
    OLD_LIBS=$LIBS
    LIBS=
    AC_CHECK_LIB(rabbitmq, amqp_basic_publish,
        [AMQP_MODULES="$AMQP_MODULES amqp.$MODULEEXT"
         AMQP_BUILT="yes"],
        [if test "x$enable_amqp" == "xcheck"; then
            AC_MSG_NOTICE([NOTICE: not building amqp module, no rabbitmq library found])
            AMQP_BUILT="no"
         else
            AC_MSG_ERROR([*** can't build amqp, no -lrabbitmq ***])
         fi
        ]
    )
    LIBS=$OLD_LIBS
])

AC_CHECK_LIB(nghttp2, nghttp2_session_get_stream_user_data, ,
             [ AC_MSG_ERROR([*** libnghttp2 required ***]) ])
AC_ARG_ENABLE([wslay],
    AS_HELP_STRING([--disable-wslay], [Disable websockets (libwslay)]))

AS_IF([test "x$enable_wslay" != "xno"], [
  AC_CHECK_LIB(wslay, wslay_event_context_server_init, [
    AC_DEFINE(HAVE_WSLAY, [1], [have libwslay])
    LIBS="-lwslay $LIBS"
  ], [
    AC_MSG_ERROR([*** can't build websocket support, no -lwslay ***])
  ])
  EXTRA_EXAMPLES="$EXTRA_EXAMPLES websocket_client websocket_server"
])

AC_CHECK_FUNCS(posix_madvise madvise)

# Let us avoid some things that displease valgrind
AC_CHECK_HEADERS(valgrind/valgrind.h)

AC_CHECK_HEADERS(priv.h)
AC_CHECK_FUNCS(setppriv)

# Some libraries provide an unparse_lower command
# we use that, so if it isn't present, we'll need
# to implement it.
AC_CHECK_FUNC(fdwalk, [AC_DEFINE(HAVE_FDWALK, [1], [have fdwalk])], )
AC_CHECK_LIB(util, openpty, , )
AC_CHECK_LIB(termcap, tputs, , )
AC_CHECK_LIB(curses, clear, , [AC_MSG_ERROR([curses not found, but required])])

if test "$enable_lmdb" != "no"; then
  if test "x$BUILD_ASAN" = "x"; then
      AC_CHECK_LIB(lmdb, mdb_dbi_open,[AC_DEFINE(HAVE_LMDB, [1], [have LMDB])
  LIBS="-llmdb $LIBS"], [AC_MSG_ERROR([lmdb not found, but required])])
  else
      AC_CHECK_LIB(lmdb-asan, mdb_dbi_open,[AC_DEFINE(HAVE_LMDB, [1], [have LMDB])
  LIBS="-llmdb-asan $LIBS"], [AC_MSG_ERROR([lmdb-asan not found, but required])])
  fi
fi

CPPFLAGS="$CPPFLAGS `pcre-config --cflags`"
LIBS="$LIBS `pcre-config --libs`"
AC_CHECK_HEADER(pcre.h, [], [AC_MSG_ERROR([*** pcre (headers) required ***])])
AC_CHECK_LIB(pcre, pcre_compile, ,
	[
		AC_MSG_ERROR([libpcre not found, but required])
	]
)

AC_MSG_CHECKING([for OpenSSL version >= 1.0.2])
AC_TRY_COMPILE([
#include <openssl/opensslv.h>
    ],
    [
#if !defined(OPENSSL_VERSION_NUMBER)
#error "Missing OpenSSL version"
#endif
#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error "OpenSSL 1.0.2 or higher is required"
#endif
    ],
    [AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)
     AC_MSG_ERROR([OpenSSL version is too old or cannot be determined])]
)

AC_CHECK_LIB(crypto, ERR_load_CRYPTO_strings, ,
	[
		AC_MSG_ERROR([libcrypto not found, but required])
	]
)
AC_CHECK_LIB(ssl, OPENSSL_init_ssl, , [
AC_CHECK_LIB(ssl, SSL_library_init, ,
	[
		AC_MSG_ERROR([libssl not found, but required])
	]
)
])

AC_CHECK_FUNC(SSL_CTX_set_next_protos_advertised_cb, ,
              [AC_DEFINE(OPENSSL_NO_NEXTPROTONEG, [1], [OPENSSL_NO_NEXTPROTONEG])])

AC_MSG_CHECKING([libxml2 cflags])
XML2CFLAGS=`xml2-config --cflags`
CFLAGS="$CFLAGS $XML2CFLAGS"
CXXFLAGS="$CXXFLAGS $XML2CFLAGS" 
AC_MSG_RESULT([$XML2CFLAGS])
AC_CHECK_HEADER(libxml/tree.h, [], [AC_MSG_ERROR([*** libxml2 (headers) required ***])])

AC_MSG_CHECKING([libxml2 libs])
XML2LIBS=`xml2-config --libs`
LIBS="$LIBS $XML2LIBS"
AC_MSG_RESULT([$XML2LIBS])

AC_CHECK_FUNC(xmlParseDocument, , [AC_MSG_ERROR([*** libxml2 is required ***])])

AC_MSG_CHECKING([libxslt cflags])
XSLTCFLAGS=`xslt-config --cflags`
CFLAGS="$CFLAGS $XSLTCFLAGS"
CXXFLAGS="$CXXFLAGS $XSLTCFLAGS"
AC_MSG_RESULT([$XSLTCFLAGS])
AC_CHECK_HEADER(libxslt/xslt.h, [], [AC_MSG_ERROR([*** libxslt (headers) required ***])])

AC_MSG_CHECKING([libxslt libs])
XSLTLIBS=`xslt-config --libs`
LIBS="$LIBS $XSLTLIBS"
AC_MSG_RESULT([$XSLTLIBS])

AC_CHECK_FUNC(xsltParseStylesheetDoc, , [AC_MSG_ERROR([*** libxslt is required ***])])

LIBMTEV_LIBS=$LIBS
AC_SUBST(LIBMTEV_LIBS)
AC_SUBST(EXAMPLE_LIBS)

AC_CHECK_FUNC(SSLv2_server_method, [ AC_DEFINE(HAVE_SSLV2_SERVER, [1], [SSLv2_server_method]) ])
AC_CHECK_FUNC(SSLv2_client_method, [ AC_DEFINE(HAVE_SSLV2_CLIENT, [1], [SSLv2_client_method]) ])
AC_CHECK_FUNC(SSLv3_server_method, [ AC_DEFINE(HAVE_SSLV3_SERVER, [1], [SSLv3_server_method]) ])
AC_CHECK_FUNC(SSLv3_client_method, [ AC_DEFINE(HAVE_SSLV3_CLIENT, [1], [SSLv3_client_method]) ])
AC_CHECK_FUNC(TLSv1_server_method, [ AC_DEFINE(HAVE_TLSV1_SERVER, [1], [TLSv1_server_method]) ])
AC_CHECK_FUNC(TLSv1_client_method, [ AC_DEFINE(HAVE_TLSV1_CLIENT, [1], [TLSv1_client_method]) ])
AC_CHECK_FUNC(TLSv1_1_server_method, [ AC_DEFINE(HAVE_TLSV1_1_SERVER, [1], [TLSv1_1_server_method]) ])
AC_CHECK_FUNC(TLSv1_1_client_method, [ AC_DEFINE(HAVE_TLSV1_1_CLIENT, [1], [TLSv1_1_client_method]) ])
AC_CHECK_FUNC(TLSv1_2_server_method, [ AC_DEFINE(HAVE_TLSV1_2_SERVER, [1], [TLSv1_2_server_method]) ])
AC_CHECK_FUNC(TLSv1_2_client_method, [ AC_DEFINE(HAVE_TLSV1_2_CLIENT, [1], [TLSv1_2_client_method]) ])

AC_TRY_LINK([],
    [ issetugid(); ],
    [ AC_DEFINE(HAVE_ISSETUGID, [1], [Have issetugid(2).]) ],
    [ ]
)

AC_MSG_CHECKING([whether sem_init works])
AC_TRY_RUN(
	[
#include <semaphore.h>
int main(void){sem_t s;return (0 != sem_init(&s,0,0));}
	],
	[
		AC_MSG_RESULT(yes)
		AC_DEFINE(WORKING_SEM_INIT, [1], [have sem_init])
	], 
	[
		AC_MSG_RESULT(no)
		AC_MSG_WARN([****** sem_init() is broken, I'll implement one myself.])
	]
)

AC_MSG_CHECKING([whether memmem works])
AC_TRY_RUN(
	[
#include <string.h>
int main(void){
	const char *hay = "hay_for_horses";
	return (memmem(hay, strlen(hay), "for_", 4) != (hay+4) || memmem(hay, strlen(hay), "Z", 0) != hay);
}
	],
	[
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_RESULT(no)
		AC_MSG_WARN([****** memmem busted, using an internal version])
		AC_DEFINE(BROKEN_MEMMEM, [1], [broken  memmem])
	]
)

AC_FUNC_STRFTIME
AC_CHECK_FUNCS(ssetugid strlcpy strnstrn openpty inet_pton inet_ntop getopt \
	poll vasprintf strlcat strndup vasprintf pthread_sigqueue)

# Checks for header files.
AC_CHECK_HEADERS(sys/file.h sys/types.h dirent.h sys/param.h fcntl.h errno.h limits.h \
	sys/resource.h sys/uio.h pthread.h semaphore.h pwd.h stdio.h stdlib.h string.h \
	ctype.h unistd.h time.h pty.h sys/stat.h sys/event.h libkern/OSAtomic.h \
	termio.h termios.h curses.h sys/cdefs.h grp.h netinet/in_systm.h \
	sys/ioctl_compat.h sys/filio.h util.h sys/time.h sys/mman.h \
	sys/ioctl.h stropts.h sys/stream.h alloca.h sys/wait.h bsd/libutil.h libutil.h \
	stdint.h inttypes.h endian.h sys/endian.h umem.h pthread_np.h)

AC_CHECK_HEADERS([term.h], [], [],
	[[
#ifdef HAVE_CURSES_H
# include <curses.h>
#endif
	]])

AC_CHECK_DECLS([openpty], [], [],
	[
#if defined(HAVE_SYS_TYPES_H)
# include <sys/types.h>
#endif
#if defined(HAVE_SYS_IOCTL_H)
# include <sys/ioctl.h>
#endif
#if defined(HAVE_TERMIOS_H)
# include <termios.h>
#endif
#if defined(HAVE_BSD_LIBUTIL_H)
# include <bsd/libutil.h>
#elif defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#endif
#if defined(HAVE_UTIL_H)
# include <util.h>
#endif
#if defined(HAVE_PTY_H)
# include <pty.h>
#endif
	])

AC_CHECK_FUNCS(getpwnam_r)
HAVE_GETPWNAM_R_POSIX=""
AC_MSG_CHECKING(for POSIX.1c getpwnam_r)
AC_TRY_LINK([
#include <pwd.h>
#include <stdlib.h>],
  getpwnam_r(NULL,NULL,NULL,0,NULL);,
  AC_DEFINE(HAVE_GETPWNAM_R_POSIX,1,POSIX.1c getpwnam_r)
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no))

AC_CHECK_FUNCS(getgrnam_r)
HAVE_GETGRNAM_R_POSIX=""
AC_MSG_CHECKING(for POSIX.1c getgrnam_r)
AC_TRY_LINK([
#include <grp.h>
#include <stdlib.h>],
  getgrnam_r(NULL,NULL,NULL,0,NULL);,
  AC_DEFINE(HAVE_GETGRNAM_R_POSIX,1,POSIX.1c getgrnam_r)
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no))

AC_MSG_CHECKING(for tputs() function final argument type)
AC_EGREP_CPP([tputs.*[(][       ]*char[         ]*[)]],
		[#if defined(HAVE_TERM_H)
		 #include <term.h>
		 #endif
		 #if defined(HAVE_CURSES_H)
		 #include <curses.h>
		 #endif],
		[AC_MSG_RESULT(char)
		 AC_DEFINE(TPUTS_TAKES_CHAR, [1], [tpus takes char])],
		[AC_MSG_RESULT(not char)])

AC_MSG_CHECKING(for tgoto() function final argument type)
AC_EGREP_CPP([tgoto.*[(][       ]*char[         ]*],
		[#if defined(HAVE_TERM_H)
		 #include <term.h>
		 #endif
		 #if defined(HAVE_CURSES_H)
		 #include <curses.h>
		 #endif],
		[AC_MSG_RESULT(char)
		 AC_DEFINE(TGOTO_TAKES_CHAR, [1], [tgoto takes char])],
		[AC_MSG_RESULT(not char)])

AC_CACHE_CHECK([for kqueue support], ac_cv_have_kqueue, [
	AC_TRY_LINK(
		[ #include <sys/types.h>
		  #include <sys/event.h>
		  #include <sys/time.h> ],
		[ int a; a = kqueue(); (void)a;],
		[ ac_cv_have_kqueue="yes" ],
		[ ac_cv_have_kqueue="no" ]
	)
])
if test "x$ac_cv_have_kqueue" = "xyes" ; then
	AC_DEFINE(HAVE_KQUEUE, [1], [have kqueue])
	EVENTER_OBJS="$EVENTER_OBJS eventer_kqueue_impl.lo"
	AC_DEFINE_UNQUOTED(DEFAULT_EVENTER, "kqueue", [default eventer])
	have_kqueue=1
fi

AC_CACHE_CHECK([for epoll support], ac_cv_have_epoll, [
	AC_TRY_LINK(
		[ #include <sys/epoll.h> ],
		[ int a; a = epoll_create(0); (void)a;],
		[ ac_cv_have_epoll="yes" ],
		[ ac_cv_have_epoll="no" ]
	)
])
AC_CHECK_HEADERS(sys/eventfd.h)
if test "x$ac_cv_have_epoll" = "xyes" ; then
	AC_DEFINE(HAVE_EPOLL, [1], [epoll])
	EVENTER_OBJS="$EVENTER_OBJS eventer_epoll_impl.lo"
	AC_DEFINE_UNQUOTED(DEFAULT_EVENTER, "epoll", [default eventer])
	have_epoll=1
fi

AC_CACHE_CHECK([for Solaris ports support], ac_cv_have_ports, [
	AC_TRY_LINK(
		[ #include <port.h> ],
		[ int a; a = port_create(); (void)a; ],
		[ ac_cv_have_ports="yes" ],
		[ ac_cv_have_ports="no" ]
	)
])
if test "x$ac_cv_have_ports" = "xyes" ; then
	AC_DEFINE(HAVE_PORTS, [1], [have ports])
	EVENTER_OBJS="$EVENTER_OBJS eventer_ports_impl.lo"
	AC_DEFINE_UNQUOTED(DEFAULT_EVENTER, "ports", [default eventer])
	have_ports=1
fi

AC_SUBST(EVENTER_OBJS)

AC_CACHE_CHECK([for posix_readdir_r], ac_cv_have_posix_readdir_r, [
	AC_TRY_COMPILE(
		[ #include <dirent.h> ], 
		[ struct dirent *dep, de; DIR *d = opendir("/");  readdir_r(d, &de, &dep); (void)dep; (void)de; ], 
		[ ac_cv_have_posix_readdir_r="yes" ],
		[ ac_cv_have_posix_readdir_r="no" ]
	)
])
if test "x$ac_cv_have_posix_readdir_r" = "xyes" ; then
	AC_DEFINE(HAVE_POSIX_READDIR_R, [1], [have readdir_r])
	have_posix_readdir_r=1
fi

AC_CACHE_CHECK([for sig_t type], ac_cv_have_sig_t, [
	AC_TRY_COMPILE(
		[ #include <signal.h> ], 
		[ sig_t a; (void)a;], 
		[ ac_cv_have_sig_t="yes" ],
		[ ac_cv_have_sig_t="no" ]
	)
])
if test "x$ac_cv_have_sig_t" = "xyes" ; then
	AC_DEFINE(HAVE_SIG_T, [1], [have sig_t])
	have_sig_t=1
fi

AC_CACHE_CHECK([for htobe64], ac_cv_have_htobe64, [
	AC_TRY_LINK(
		[ #include <endian.h> ],
		[ long long int a; a = htobe64(1); (void)a;],
		[ ac_cv_have_htobe64="yes" ],
		[ ac_cv_have_htobe64="no" ]
	)
])

if test "x$ac_cv_have_htobe64" != "xyes" ; then
unset ac_cv_have_htobe64
AC_CACHE_CHECK([for htobe64], ac_cv_have_htobe64, [
	AC_TRY_LINK(
		[ #include <sys/endian.h> ],
		[ long long int a; a = htobe64(1); (void)a;],
		[ ac_cv_have_htobe64="yes" ],
		[ ac_cv_have_htobe64="no" ]
	)
])
fi

AC_CACHE_CHECK([for be64toh], ac_cv_have_be64toh, [
  AC_TRY_LINK(
    [ #include <endian.h> ],
    [ long long int a; a = be64toh(1); (void)a;],
    [ ac_cv_have_be64toh="yes" ],
    [ ac_cv_have_be64toh="no" ]
  )
])

if test "x$ac_cv_have_be64toh" != "xyes" ; then
unset ac_cv_have_be64toh
AC_CACHE_CHECK([for be64toh], ac_cv_have_be64toh, [
	AC_TRY_LINK(
		[ #include <sys/endian.h> ],
		[ long long int a; a = be64toh(1); (void)a;],
		[ ac_cv_have_be64toh="yes" ],
		[ ac_cv_have_be64toh="no" ]
	)
])
fi

AC_CACHE_CHECK([for htonll], ac_cv_have_htonll, [
	AC_TRY_LINK(
		[ #include <endian.h> ],
		[ long long int a; a = htonll(1); (void)a;],
		[ ac_cv_have_htonll="yes" ],
		[ ac_cv_have_htonll="no" ]
	)
])

if test "x$ac_cv_have_htonll" = "xno" -a "x$ac_cv_have_htobe64" = "xyes" ; then
	AC_DEFINE(MAKE_HTOBE64_HTONLL, [1], [have htonll])
fi
if test "x$ac_cv_have_htonll" = "xno" -a "x$ac_cv_have_be64toh" = "xyes" ; then
  AC_DEFINE(MAKE_BE64TOH_NTOHLL, [1], [have ntohll])
fi

AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INTPTR_T
AC_TYPE_INTMAX_T
AC_TYPE_LONG_LONG_INT

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINTPTR_T
AC_TYPE_UINTMAX_T
AC_TYPE_UNSIGNED_LONG_LONG_INT

AC_TYPE_LONG_DOUBLE
AC_TYPE_LONG_LONG_INT
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CACHE_CHECK([for socklen_t], ac_cv_have_socklen_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
#include <sys/socket.h>
		],
		[socklen_t foo; foo = 1235; (void)foo;], ,
		[ AC_MSG_ERROR(socklen_t is missing) ]
	)
])

AC_CACHE_CHECK([for size_t], ac_cv_have_size_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ size_t foo; foo = 1235; (void)foo;], ,
		[ AC_MSG_ERROR(size_t is missing) ]
	)
])

AC_CACHE_CHECK([for ssize_t], ac_cv_have_ssize_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ ssize_t foo; foo = 1235; (void)foo;], ,
		[ AC_MSG_ERROR(ssize_t is missing) ]
	)
])

AC_SUBST(FQ_MODULES)
AC_SUBST(KAFKA_MODULES)
AC_SUBST(AMQP_MODULES)
AC_SUBST(LUA_MODULES)

if test "$enable_coverage" != "no"; then
	CFLAGS="$CFLAGS --coverage"
	SHCLAGS="$SHCFLAGS --coverage"
	LDFLAGS="$LDFLAGS --coverage"
	SHLDFLAGS="$SHLDFLAGS --coverage"
fi

docdir="docs"
mansubdir="man"
AC_SUBST(docdir)
AC_SUBST(mansubdir)
SHCFLAGS="$PICFLAGS $CFLAGS"
SHCXXFLAGS="$PICFLAGS $CXXFLAGS"
AC_SUBST(SHCFLAGS)
AC_SUBST(SHCXXFLAGS)
AC_SUBST(LD)
AC_SUBST(SHLDFLAGS)
AC_SUBST(EXTRA_EXAMPLES)

if test -n "`$CC -V 2>&1 | grep 'Sun C'`"; then
	if test "$enable_string" != "no"; then
		CFLAGS="$CFLAGS -errwarn=%all"
	fi
elif test -n "`$CC --version 2>&1 | grep 'clang'`"; then
	CFLAGSEXTRAS="$CFLAGSEXTRAS -Wall -Wextra"
	if test "$enable_string" != "no"; then
		CFLAGSEXTRAS="$CFLAGSEXTRAS -Werror"
	fi
else
	CFLAGSEXTRAS="$CFLAGSEXTRAS -Wall -Wextra -Wold-style-declaration"
	if test "$enable_strict" != "no"; then
		CFLAGSEXTRAS="$CFLAGSEXTRAS -Werror"
	fi
fi
AC_SUBST(CFLAGSEXTRAS)

AC_SUBST(CXXFLAGSEXTRAS)

UNAME_V=`uname -v`
UNAME_R=`uname -r`
UNAME_S=`uname -s`
UNAME_M=`uname -m`
UNAME_N=`uname -n`
UNAME_P=`uname -p`
AC_DEFINE_UNQUOTED(UNAME_V, "$UNAME_V", [uname -v])
AC_DEFINE_UNQUOTED(UNAME_R, "$UNAME_R", [uname -r])
AC_DEFINE_UNQUOTED(UNAME_S, "$UNAME_S", [uname -s])
AC_DEFINE_UNQUOTED(UNAME_M, "$UNAME_M", [uname -m])
AC_DEFINE_UNQUOTED(UNAME_N, "$UNAME_N", [uname -n])
AC_DEFINE_UNQUOTED(UNAME_P, "$UNAME_P", [uname -p])

AC_OUTPUT([
Makefile
src/Makefile
src/man/Makefile
src/modules/Makefile
src/examples/Makefile
src/scripts/mtev-config
src/utils/android-demangle/Makefile
test/Makefile
test/mtevbusted-script
])

AC_MSG_RESULT([

=== Compile-time Configuration ===

  == Compilers ==
  CC:                 $CC
  CXX:                $CXX
  CPPFLAGS:           $CPPFLAGS
  CFLAGS:             $CFLAGS
  CXXFLAGS:           $CXXFLAGS
  LD:                 $LD
  CLINKFLAGS:         $CLINKFLAGS
  MAPFLAGS:           $MAPFLAGS

  SHCFLAGS:           $SHCFLAGS
  SHCXXFLAGS:         $SHCXXFLAGS
  SHLD:               $SHLD

  MODULECC:           $MODULECC
  MODULESHCFLAGS:     $MODULESHCFLAGS
  MODULESHCXXFLAGS:   $MODULESHCXXFLAGS

  MODULELD:           $MODULELD
  MODULESHLDFLAGS:    $MODULESHLDFLAGS

  == Optional modules ==
  AMQP module:        $AMQP_BUILT
  FQ module:          $FQ_BUILT
  Zipkin-fq module:   $ZIPKIN_FQ_BUILT
  Kafka module:       $KAFKA_BUILT

  == Target ==
  Target library:      $TGT_NAME

])
