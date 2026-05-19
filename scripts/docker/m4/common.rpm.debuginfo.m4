#
#  Enable the Rocky debug repos and install debuginfo packages for
#  the FreeRADIUS runtime library closure. Failure is fatal so a
#  renamed or split debuginfo package gets caught at image-build
#  time rather than silently producing an image without symbols.
#
#  The *-debug repos exist on Rocky 9 and 10; gpgcheck stays on so
#  a mirror compromise can't smuggle in unsigned debuginfo.
#
RUN dnf install -y dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf config-manager --set-enabled baseos-debug && \
    dnf config-manager --set-enabled appstream-debug && \
    dnf config-manager --set-enabled crb-debug && \
    dnf install -y \
        glibc-debuginfo \
        zlib-debuginfo \
        readline-debuginfo \
        openssl-libs-debuginfo \
        cyrus-sasl-lib-debuginfo \
        pam-debuginfo \
        openldap-debuginfo \
        libtalloc-debuginfo \
        pcre2-debuginfo \
        libpcap-debuginfo \
        unbound-libs-debuginfo \
        sqlite-libs-debuginfo \
        libpq-debuginfo \
        mariadb-connector-c-debuginfo \
        gdbm-libs-debuginfo \
        json-c-debuginfo \
        brotli-debuginfo \
        hiredis-debuginfo \
        librdkafka-debuginfo \
        libcurl-debuginfo && \
    dnf clean all
