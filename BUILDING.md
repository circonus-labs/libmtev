#Building Mount Everest (libmtev)

## Requirements

 * libck
 * libjlog
 * luajit
 * fq

## Platforms

### FreeBSD

    #!/bin/sh
    # portmaster -g /usr/ports/misc/e2fsprogs-libuuid
    # portmaster -g /usr/ports/devel/pcre
    # portmaster -g /usr/ports/devel/concurrencykit
    # portmaster -g /usr/ports/devel/hwloc
    # portmaster -g /usr/ports/devel/re2c
    # portmaster -g /usr/ports/textproc/libxml2
    # portmaster -g /usr/ports/textproc/libxslt
    # cd /usr/local/src
    # git clone https://github.com/circonus-labs/libmtev
    # cd libmtev
    # aclocal
    # autoconf
    # ./configure LDFLAGS="-L/usr/local/lib"
    # make

### Linux (Debian)

    #!/bin/sh
    # apt-get install autoconf build-essential \
		zlib1g-dev uuid-dev libpcre3-dev libssl-dev \
		libxslt-dev xsltproc  libncurses5-dev hwloc-nox-dev libck0-dev
		# git clone https://github.com/circonus-labs/libmtev
		# cd libmtev
		# autoconf
		# LDFLAGS="-ldl -lm" ./configure
		# make

### Linux (CentOS 6.3)

    #!/bin/sh
    # yum install autoconf \
    	libtermcap-devel libxslt-devel ncurses-devel openssl-devel \
    	pcre-devel uuid-devel zlib-devel \
    	libuuid-devel hwloc-devel ck
    # git clone https://github.com/circonus-labs/libmtev
    # cd libmtev
    # autoconf
    # ./configure
    # make

### OmniOS

        # pkg set-publisher -g http://updates.circonus.net/omnios/ circonus
        # pkg install developer/git developer/build/autoconf system/header \
                developer/gcc48 developer/build/gnu-make \
                platform/library/hwloc field/ck jlog luajit udns fq

        # git clone git@github.com:circonus-labs/libmtev.git
        # cd libmtev
        # autoconf
        # ./configure LDFLAGS="-m64 -L/opt/circonus/lib/amd64" CPPFLAGS="-I/opt/circonus/include/amd64"
        # export MAKE=gmake
        # gmake
