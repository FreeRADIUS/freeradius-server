changequote([,])dnl
#
#  Debug symbols for the FreeRADIUS runtime library closure.
#
#  Repo source depends on derivative:
#    ubuntu     ddebs.ubuntu.com with ubuntu-dbgsym-keyring
#    debian     debian-debug.debian.net via the existing debian-archive
#               keyring (no extra keyring install)
#
#  Glibc-linked libs gained the t64 suffix in ubuntu 24.04 and debian
#  13. T64 expands accordingly; `[]' breaks the surrounding token so
#  m4 actually expands the macro mid-package-name.
#
#  Failure is fatal -- a renamed or retired -dbgsym package gets
#  caught at image-build time, not in production when a profiler
#  tries to resolve a symbol that isn't there.
#
define([T64], [ifelse(OS_NAME, [ubuntu], [ifelse(eval(OS_VER >= 24), 1, [t64])],
                      OS_NAME, [debian], [ifelse(eval(OS_VER >= 13), 1, [t64])])])dnl
ifelse(OS_NAME, [ubuntu], [dnl
RUN apt-get update && \
    apt-get install -y $APT_OPTS ubuntu-dbgsym-keyring && \
    printf 'deb http://ddebs.ubuntu.com OS_CODENAME main restricted universe multiverse\ndeb http://ddebs.ubuntu.com OS_CODENAME-updates main restricted universe multiverse\n' \
        > /etc/apt/sources.list.d/ddebs.list && \
    apt-get update && \],
       OS_NAME, [debian], [dnl
RUN printf 'deb http://debian-debug.debian.net/debian-debug OS_CODENAME-debug main\n' \
        > /etc/apt/sources.list.d/debian-debug.list && \
    apt-get update && \],
       [errprint([common.deb.dbgsym.m4: unsupported OS_NAME=]OS_NAME[
])m4exit(1)])dnl
    apt-get install -y $APT_OPTS \
        libc6-dbg \
        zlib1g-dbgsym \
        libreadline8[]T64[]-dbgsym \
        libssl3[]T64[]-dbgsym \
        libsasl2-2-dbgsym \
        libpam0g-dbgsym \
        libldap2-dbgsym \
        libtalloc2-dbgsym \
        libpcre2-8-0-dbgsym \
        libpcap0.8[]T64[]-dbgsym \
        libunbound8-dbgsym \
        libsqlite3-0-dbgsym \
        libpq5-dbgsym \
        libmariadb3-dbgsym \
        libgdbm6[]T64[]-dbgsym \
        libjson-c5-dbgsym \
        libbrotli1-dbgsym \
        libhiredis1.1.0-dbgsym \
        librdkafka1-dbgsym \
        libwbclient0-dbgsym \
        libcurl4[]T64[]-dbgsym && \
    apt-get clean && \
    rm -r /var/lib/apt/lists/*
undefine([T64])dnl
changequote(`,')dnl
