#
#  Debug symbols for the FreeRADIUS runtime library closure. We use
#  `dnf debuginfo-install` (from dnf-plugins-core) because Rocky's
#  debug repo naming has shifted between versions; the plugin walks
#  the package metadata and enables whichever *-debug repo provides
#  the matching debuginfo rpm.
#
#  Failure is fatal -- a renamed or split debuginfo package gets
#  caught at image-build time rather than silently producing an
#  image without symbols.
#
RUN dnf install -y dnf-plugins-core && \
    dnf debuginfo-install -y \
        glibc \
        zlib \
        readline \
        openssl-libs \
        cyrus-sasl-lib \
        pam \
        openldap \
        libtalloc \
        pcre2 \
        libpcap \
        unbound-libs \
        sqlite-libs \
        libpq \
        mariadb-connector-c \
        gdbm-libs \
        json-c \
        brotli \
        hiredis \
        librdkafka \
        libcurl && \
    dnf clean all
