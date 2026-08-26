changequote([,])dnl
#
#  Debug symbols for the FreeRADIUS runtime library closure.
#
#  Package list is empirically derived per Rocky major (probed against
#  the crossbuild images with baseos/appstream/crb debug repos
#  enabled). The install is a single dnf invocation: if any package
#  goes missing in upstream we want the build to fail fast, not ship
#  a profiling image with half its symbols.
#
#  Differences between releases:
#    rocky9   zlib-debuginfo + python3.9-debuginfo
#    rocky10  zlib-ng-compat-debuginfo + python3.12-debuginfo
#  hiredis has no -debuginfo in either EL release.
#
#  The crb / *-debuginfo repos need explicit enabling; baseos-debug is
#  not in the default repo set even though the repo files exist.
#
RUN dnf install -y dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf config-manager --set-enabled baseos-debuginfo appstream-debuginfo crb-debuginfo extras-debuginfo && \
    dnf install -y \
        glibc-debuginfo \
        ifelse(eval(OS_VER >= 10), 1, [zlib-ng-compat-debuginfo], [zlib-debuginfo]) \
        readline-debuginfo \
        openssl-libs-debuginfo \
        cyrus-sasl-lib-debuginfo \
        pam-debuginfo \
        openldap-debuginfo \
        libtalloc-debuginfo \
        pcre2-debuginfo \
        libpcap-debuginfo \
        unbound-debuginfo \
        unbound-libs-debuginfo \
        sqlite-debuginfo \
        sqlite-libs-debuginfo \
        libpq-debuginfo \
        mariadb-connector-c-debuginfo \
        gdbm-debuginfo \
        gdbm-libs-debuginfo \
        json-c-debuginfo \
        brotli-debuginfo \
        libbrotli-debuginfo \
        librdkafka-debuginfo \
        libwbclient-debuginfo \
        libcurl-debuginfo \
        krb5-libs-debuginfo \
        libxml2-debuginfo \
        libidn2-debuginfo \
        ifelse(eval(OS_VER >= 10), 1, [python3.12-debuginfo], [python3.9-debuginfo])
changequote(`,')dnl
