#
#  Build libkqueue from source as proper RPMs (libkqueue, libkqueue-devel,
#  libkqueue-debuginfo) so downstream dnf-builddep / Requires steps find
#  the -devel and so a debugger sees symbols.
#
#  Rocky's arm64 archives don't currently ship libkqueue at all, and the
#  upstream project's own packaging keeps default optimisation flags that
#  strip the symbols we care about -- RelWithDebInfo with explicit C
#  flags overrides that and CPACK_RPM_DEBUGINFO_PACKAGE=ON makes cpack
#  emit a separate -debuginfo package alongside the main rpm.
#
#  Build out-of-tree (separate build dir) because cpack's debuginfo
#  generator demands a source-vs-build path distinction to relocate
#  debug records.
#
RUN dnf install -y gcc make cmake git rpm-build && \
    git clone --depth 1 https://github.com/mheily/libkqueue.git /tmp/libkqueue-from-source-for-debuginfo-packaging && \
    mkdir /tmp/libkqueue-from-source-build && \
    cd /tmp/libkqueue-from-source-build && \
    cmake -G "Unix Makefiles" \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib64 \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS_RELWITHDEBINFO="-g3 -O1 -fno-omit-frame-pointer -DNDEBUG" \
        -DCPACK_RPM_DEBUGINFO_PACKAGE=ON \
        -DCPACK_BUILD_SOURCE_DIRS=/tmp/libkqueue-from-source-for-debuginfo-packaging \
        /tmp/libkqueue-from-source-for-debuginfo-packaging && \
    make && \
    cpack -G RPM && \
    rpm -i --force libkqueue*.rpm && \
    mkdir -p /opt/libkqueue-rpms && cp libkqueue*.rpm /opt/libkqueue-rpms/ && \
    cd / && rm -rf /tmp/libkqueue-from-source-for-debuginfo-packaging /tmp/libkqueue-from-source-build
