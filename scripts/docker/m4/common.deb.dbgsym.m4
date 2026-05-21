changequote([,])dnl
#
#  Debug symbols for the FreeRADIUS runtime library closure.
#
#  Repo source depends on derivative:
#    ubuntu     ddebs.ubuntu.com with ubuntu-dbgsym-keyring
#    debian     debug.mirrors.debian.org via the existing debian-archive
#               keyring (no extra keyring install)
#
#  Package list is empirically derived per codename (apt-cache against
#  the crossbuild images). The install is a single apt-get with no
#  per-package fallback: if a package goes missing in upstream ddebs
#  the build fails fast and the operator updates this template, rather
#  than silently shipping a profiling image with no symbols for half
#  the runtime closure.
#
#  Glibc-linked libs gained the t64 suffix in ubuntu 24.04 and debian
#  13. T64 expands to "t64" on those releases. The same boundary also
#  picks the libldap and libhiredis soname names, so PRE_T64 captures
#  pre-transition releases (bookworm, jammy) as 1.
#
#  We deliberately do NOT `apt-get clean / rm -r /var/lib/apt/lists/*'
#  here: the cache would invalidate every subsequent apt-get install
#  in the containing template and force a redundant apt-get update.
#
define([T64], [ifelse(OS_NAME, [ubuntu], [ifelse(eval(OS_VER >= 24), 1, [t64])],
                      OS_NAME, [debian], [ifelse(eval(OS_VER >= 13), 1, [t64])])])dnl
define([PRE_T64], [ifelse(OS_NAME, [ubuntu], [ifelse(eval(OS_VER >= 24), 1, 0, 1)],
                          OS_NAME, [debian], [ifelse(eval(OS_VER >= 13), 1, 0, 1)])])dnl
ifelse(OS_NAME, [ubuntu], [dnl
RUN apt-get update && \
    apt-get install -y $APT_OPTS ubuntu-dbgsym-keyring && \
    printf 'deb http://ddebs.ubuntu.com OS_CODENAME main restricted universe multiverse\ndeb http://ddebs.ubuntu.com OS_CODENAME-updates main restricted universe multiverse\n' \
        > /etc/apt/sources.list.d/ddebs.list],
       OS_NAME, [debian], [dnl
RUN printf 'deb http://debug.mirrors.debian.org/debian-debug OS_CODENAME-debug main\n' \
        > /etc/apt/sources.list.d/debian-debug.list],
       [errprint([common.deb.dbgsym.m4: unsupported OS_NAME=]OS_NAME[
])m4exit(1)])

RUN apt-get update && apt-get install -y $APT_OPTS \
        libc6-dbg \
        zlib1g-dbgsym \
        libreadline8[]T64[]-dbgsym \
        libssl3[]T64[]-dbgsym \
        libsasl2-2-dbgsym \
        libpam0g-dbgsym \
        ifelse(PRE_T64, 1, [libldap-2.5-0-dbgsym], [libldap2-dbgsym]) \
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
        ifelse(PRE_T64, 1, [libhiredis0.14-dbgsym], [libhiredis1.1.0-dbgsym]) \
        librdkafka1-dbgsym \
        libwbclient0-dbgsym \
        libcurl4[]T64[]-dbgsym \
ifelse(OS_CODENAME, [forky], [], OS_CODENAME, [resolute], [], [dnl
        libxml2-dbgsym \
])dnl
ifelse(OS_CODENAME, [resolute], [], [dnl
        libidn12-dbgsym \
])dnl
        ifelse(OS_CODENAME, [bookworm], [python3.11-dbg],
               OS_CODENAME, [trixie],   [python3.13-dbg],
               OS_CODENAME, [forky],    [python3.13-dbg],
               OS_CODENAME, [jammy],    [python3.10-dbg],
               OS_CODENAME, [noble],    [python3.12-dbg],
               OS_CODENAME, [resolute], [],
               [])
undefine([T64])dnl
undefine([PRE_T64])dnl
changequote(`,')dnl
