# Building Mount Everest (libmtev)

## Requirements

 * stdc11 (gcc 4.9 or higher)
 * concurrencykit (ck) 0.5+
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
 * sqllite

 Optional:
 * wslay (for websockets support)
 * libunwind (for better stack traces)
 * libdwarf (for better stack traces)
 * librabbitmq-c
 * fq
 
## Platforms

### FreeBSD 10+

    You'll need to install the following from source first:
      * libcircllhist
      * libcircmetrics
      * jlog
      * fq
      * wslay-1.0.0
      * concurrencykit 0.7.0

    pkg install autoconf gcc git gmake \
        hwloc liblz4 \
        libxml2 libxslt luajit pcre udns flatcc \
        yajl e2fsprogs-libuuid rabbitmq-c lmdb

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i
    CPPFLAGS="-I/usr/local/include/luajit-2.0" ./configure
    gmake

### Linux (Ubuntu LTS)

**NOTE:** The version of libck shipped with Xenial (16.04) is too old.
You will need to build a current version from [source](http://concurrencykit.org/).

Run the following as root (sudo):

    apt-get install autoconf build-essential git \
		zlib1g-dev libpcre3-dev libssl-dev \
		libxslt1-dev xsltproc libncurses5-dev libhwloc-dev \
        libluajit-5.1-dev libudns-dev liblz4-dev \
        librabbitmq-c

Now skip forward to the section below on *Downloading and Building the Package Dependencies*.  Then come back and continue with the section below, *Building Libmtev*.

### Linux (RHEL/CentOS 6+)

**NOTE** The EPEL (Extra Packages for Enterprise Linux) repo will be used.
This is required for liblz4 and libudns.

Run the following as root (sudo):

    yum groupinstall "Development Tools"
    yum install epel-release autoconf git \
        curl-devel hwloc-devel libxslt-devel \
        lz4-devel ncurses-devel openssl-devel pcre-devel \
        udns-devel librabbitmq-c
    yum --enablerepo=extras install centos-release-scl
    yum --enablerepo=base install devtoolset-8

Now skip forward to the section below on *Downloading and Building the Package Dependencies*.  Then come back and continue with the next step, *Building Libmtev*.

### Building Libmtev (RHEL/CentOS/Ubuntu)

Once you have all the dependencies built and installed, clone the source for libmtev and follow these steps to run the build process:

    git clone https://github.com/circonus-labs/libmtev
    cd libmtev
    autoreconf -i
    CPPFLAGS="-I/usr/local/include/luajit" ./configure
    make

You may have to modify the CPPFLAGS and LDFLAGS definition to include the library headers from the right location, or otherwise you might get build errors.  For example, these settings may work for your environment:

    export CPPFLAGS="-I/opt/circonus/include -I/opt/circonus/include/luajit"`
    export LDFLAGS="-L/opt/circonus/lib -Wl,-rpath=/opt/circonus/lib"

NOTE: Make sure to rerun `./configure` after you change the definition of these flags and before you try to `make` again.

### OmniOS

Supported releases:
 * r151014 LTS

Set up a [development environment](https://omnios.omniti.com/wiki.php/DevEnv) first, then:

    pkg set-publisher -g http://updates.circonus.net/omnios/r151014/ circonus
    pkg install developer/debug/mdb developer/versioning/git \
        field/ck field/fq platform/library/hwloc platform/library/jlog \
        platform/library/libcircllhist platform/library/libcircmetrics \
        platform/library/liblz4 platform/library/udns \
        platform/library/wslay platform/runtime/luajit

    git clone git@github.com:circonus-labs/libmtev.git
    cd libmtev
    autoreconf -i
    CFLAGS="-m64" \
    CPPFLAGS="-I/opt/circonus/include/amd64 -I/opt/circonus/include -I/opt/circonus/include/amd64/luajit" \
    LDFLAGS="-m64 -L/opt/circonus/lib/amd64 -R/opt/circonus/lib/amd64" \
    ./configure
    export MAKE=gmake
    gmake

### Download and Build Package Dependencies

Gather the following as zip files and extract into subfolders of a suitable package building folder on your box:

Third-Party libraries:
[ConcurrencyKit (ck)](http://concurrencykit.org/)
[LuaJit](http://luajit.org)
[sqllite](https://www.sqlite.org/index.html)

Circonus libraries:
[jlog](https://github.com/omniti-labs/jlog)
[libcircllhist](https://github.com/circonus-labs/libcircllhist)
[libcircmetrics](https://github.com/circonus-labs/libcircmetrics)
[fq](https://github.com/circonus-labs/fq)

After downloading and extracting zips, build and install these packages per the README and BUILD instructions included with each package.  Sometimes this means `autoconf`, `./configure`, `make`, and then `sudo make install` - and sometimes only the `make` and `sudo make install` are required.
