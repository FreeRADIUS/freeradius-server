#
#  Build libkqueue from source as proper .debs (libkqueue, libkqueue-dev,
#  libkqueue-dbg) so downstream dpkg-checkbuilddeps / Build-Depends steps
#  find -dev and so a debugger sees symbols.
#
#  cpack's DEB generator emits a -dbg package whenever the build produces
#  unstripped objects; RelWithDebInfo with explicit C flags overrides
#  libkqueue's default -O2 -g -DNDEBUG so the symbols actually survive.
#
RUN apt-get install -y --no-install-recommends cmake git build-essential file && \
    git clone --depth 1 https://github.com/mheily/libkqueue.git /tmp/libkqueue && \
    cd /tmp/libkqueue && \
    cmake -G "Unix Makefiles" \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS_RELWITHDEBINFO="-g3 -O1 -fno-omit-frame-pointer -DNDEBUG" \
        -DCPACK_DEBIAN_PACKAGE_NAME=libkqueue0 \
        . && \
    make && \
    cpack -G DEB && \
    dpkg -i libkqueue*.deb && \
    mkdir -p /opt/libkqueue-debs && cp libkqueue*.deb /opt/libkqueue-debs/ && \
    cd / && rm -rf /tmp/libkqueue
