# Building Mount Everest (libmtev)

## Requirements

 * C11 compiler (e.g., gcc >= 4.9, clang >= 3.6)
 * concurrencykit (ck) >= 0.7.0
 * hwloc
 * flatcc >= 0.6.0
 * jlog >= 2.2
 * liblz4
 * libcircllhist
 * libcircmetrics
 * libcurl
 * luajit >= 2.1
 * ncurses
 * openssl
 * pcre
 * udns
 * sqlite3
 * wslay (for websockets support)
 * yajl

 Optional:
 * libunwind (for better stack traces)
 * libdwarf (for better stack traces)
 * librabbitmq-c (for `amqp` module)
 * fq (for `fq` and `zipkin_fq` modules)
 
## Platforms

### FreeBSD 12+

    pkg install autoconf automake e2fsprogs-libuuid flatcc gcc \
        git gmake hwloc liblz4 libtool libxml2 libxslt lmdb \
        pcre pkgconf udns yajl

If AMQP support is desired:

    pkg install rabbitmq-c

Proceed to [Downloading and Building Source
Dependencies](#donwloading-and-building-source-dependencies), build any that
aren't provided by the above packages, then return and proceed to the next
step.

Once all dependencies are installed:

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i -I buildtools
    CPPFLAGS="-I/usr/local/include/luajit-2.1" ./configure
    gmake
    sudo gmake install


### Linux (Ubuntu LTS)

    apt-get update
    apt-get install autoconf automake build-essential cmake git \
        libcurl4-openssl-dev libhwloc-dev liblmdb-dev libluajit-5.1-dev \
        liblz4-dev libncurses5-dev libnghttp2-dev libpcre3-dev libssl-dev \
        libudns-dev libxslt1-dev libyajl-dev xsltproc zlib1g-dev

If AMQP support is desired:

    apt-get install librabbitmq-dev

Proceed to [Downloading and Building Source
Dependencies](#donwloading-and-building-source-dependencies), build any that
aren't provided by the above packages, then return and proceed to the next
step.


Once all dependencies are installed:

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i -I buildtools
    ./configure
    make
    sudo make install


### Linux (RHEL/CentOS 7+)

**NOTE** Additional repos will be used for some packages:
* EPEL (Extra Packages for Enterprise Linux): libudns
* SCLo (Software Collections SIG): devtoolset-9 (gcc that fully supports C11)

Run the following as root (sudo):

    yum groupinstall "Development Tools"
    yum install epel-release
    yum install autoconf cmake git hwloc-devel libcurl-devel \
        libnghttp2-devel libuuid-devel libxslt-devel \
        lmdb-devel lz4-devel ncurses-devel openssl openssl-devel \
        pcre-devel sqlite-devel udns-devel yajl-devel
    yum install centos-release-scl
    yum install devtoolset-9

If AMQP support is desired:

    yum install librabbitmq-devel

Proceed to [Downloading and Building Source
Dependencies](#donwloading-and-building-source-dependencies) then return and
proceed to the next step.

Once all dependencies are installed:

    PATH="/opt/rh/devtoolset-9/root/bin:$PATH"
    export PATH
    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i -I buildtools
    CPPFLAGS="-I/usr/local/include/luajit-2.1" ./configure
    make
    sudo make install


### Download and Build Source Dependencies

Note: some of these may be available in packaged form for some platforms.
Review the [requirements list](#requirements) at the top of this page for
minimum versions. If a given platform does not package a new enough version,
the correct version will need to be built from source.

Gather the following as git checkouts or source archives and build each
according to its instructions:

Third-Party libraries:
* [ConcurrencyKit (ck)](https://github.com/concurrencykit/ck)
* [flatcc](https://github.com/dvidelabs/flatcc)
  * Note that the flatcc `build.sh` does not build a shared library by default.
  * Instead, use the following procedure, setting your desired install prefix
    in the shell variable `PREFIX`:
    ```
    ./scripts/initbuild.sh make
    mkdir -p build/install
    cd build/install
    cmake ../.. \
        -DBUILD_SHARED_LIBS=on \
        -DCMAKE_BUILD_TYPE=Release \
        -DFLATCC_INSTALL=on \
        -DCMAKE_INSTALL_RPATH=$PREFIX/lib \
        -DCMAKE_INSTALL_PREFIX:PATH=$PREFIX
    sudo make install
    ```
* [LuaJIT](http://luajit.org/download.html)
* [wslay](https://github.com/tatsuhiro-t/wslay)

Circonus libraries:
* [fq](https://github.com/circonus-labs/fq) (If FQ module support is desired)
* [jlog](https://github.com/omniti-labs/jlog)
* [libcircllhist](https://github.com/openhistogram/libcircllhist)
* [libcircmetrics](https://github.com/circonus-labs/libcircmetrics)

