# Building Mount Everest (libmtev)

## Requirements

 * concurrencykit (ck) 0.5+
 * fq
 * hwloc
 * jlog 2.2+
 * liblz4
 * libcircllhist
 * libcircmetrics
 * libcurl
 * luajit 2.0+
 * ncurses
 * openssl
 * pcre
 * udns
 * wslay (optional, for websockets support)
 * librabbitmq

## Platforms

### FreeBSD 10+

    pkg install autoconf gcc git gmake \
        concurrencykit e2fsprogs-libuuid hwloc liblz4 \
        libxml2 libxslt luajit pcre udns

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i
    CPPFLAGS="-I/usr/local/include/luajit-2.0" ./configure
    gmake

### Linux (Ubuntu LTS)

**NOTE:** The version of libck shipped with Xenial (16.04) is too old.
You will need to build a current version from [source](http://concurrencykit.org/).

    apt-get install autoconf build-essential git \
		zlib1g-dev uuid-dev libpcre3-dev libssl-dev \
		libxslt1-dev xsltproc libncurses5-dev libhwloc-dev \
        libluajit-5.1-dev libudns-dev liblz4-dev

    # (build and install ck, jlog, libcircllhist, libcircmetrics, and fq now)

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i
    CPPFLAGS="-I/usr/include/luajit-2.0" ./configure
    make

### Linux (RHEL/CentOS 6+)

**NOTE** The EPEL (Extra Packages for Enterprise Linux) repo will be used.
This is required for liblz4 and libudns.

    yum groupinstall "Development Tools"
    yum install epel-release autoconf git \
        curl-devel hwloc-devel libuuid-devel libxslt-devel \
        lz4-devel ncurses-devel openssl-devel pcre-devel \
        udns-devel

    # (build and install ck, luajit, jlog, libcircllhist, libcircmetrics, and fq now)

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i
    CPPFLAGS="-I/usr/local/include/luajit-2.0" ./configure
    make

### OmniOS

Supported releases:
 * r151014 LTS

Set up a [development environment](https://omnios.omniti.com/wiki.php/DevEnv) first, then:

    pkg set-publisher -g http://updates.circonus.net/omnios/r151014/ circonus
    pkg install developer/debug/mdb developer/versioning/git \
        field/ck field/fq platform/library/hwloc platform/library/jlog \
        platform/library/libcircllhist platform/library/libcircmetrics \
        platform/library/liblz4 platform/library/udns platform/library/uuid \
        platform/library/wslay platform/runtime/luajit \
        platform/library/librabbitmq-c

    git clone git@github.com:circonus-labs/libmtev.git
    cd libmtev
    autoreconf -i
    CFLAGS="-m64" \
    CPPFLAGS="-I/opt/circonus/include/amd64 -I/opt/circonus/include -I/opt/circonus/include/amd64/luajit" \
    LDFLAGS="-m64 -L/opt/circonus/lib/amd64 -R/opt/circonus/lib/amd64" \
    ./configure
    export MAKE=gmake
    gmake
