changequote([,])dnl
#
#  Debug symbols for the FreeRADIUS runtime library closure.
#
#  Repo source depends on derivative:
#    ubuntu     ddebs.ubuntu.com with ubuntu-dbgsym-keyring
#    debian     debug.mirrors.debian.org via the existing debian-archive
#               keyring (no extra keyring install)
#
#  Glibc-linked libs gained the t64 suffix in ubuntu 24.04 and debian
#  13. T64 expands accordingly; `[]' breaks the surrounding token so
#  m4 actually expands the macro mid-package-name.
#
#  Per-package install with `|| true' fallback so the structural
#  version skew on Ubuntu LTS (ddebs lagging security-patched main,
#  e.g. libpcre2-8-0-dbgsym=10.39-3build1 vs main 10.39-3ubuntu0.1)
#  doesn't wreck the whole layer. A WARNING line in the build log
#  flags any package that couldn't be installed so operators can see
#  what's missing rather than discovering it at debug time.
#
#  We deliberately do NOT `apt-get clean / rm -r /var/lib/apt/lists/*'
#  here: the cache would invalidate every subsequent apt-get install
#  in the containing template and force a redundant apt-get update.
#
define([T64], [ifelse(OS_NAME, [ubuntu], [ifelse(eval(OS_VER >= 24), 1, [t64])],
                      OS_NAME, [debian], [ifelse(eval(OS_VER >= 13), 1, [t64])])])dnl
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

RUN apt-get update && \
    for pkg in libc6-dbg libssl3[]T64[]-dbgsym libtalloc2-dbgsym libpcre2-8-0[]T64[]-dbgsym; do \
        apt-get install -y $APT_OPTS "$pkg" || echo "WARNING: could not install dbgsym package: $pkg"; \
    done
undefine([T64])dnl
changequote(`,')dnl
