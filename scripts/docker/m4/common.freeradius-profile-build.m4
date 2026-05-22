#
#  Build and install FreeRADIUS with profiling-friendly CFLAGS into the
#  profiling image. Layered on top of the crossbuild base, which already
#  provides build deps and a clone of the upstream source at
#  /usr/local/src/repositories/freeradius-server. The local checkout is
#  copied in over the top so the image reflects the branch under test,
#  not whatever was on upstream master at image build time.
#
#  CFLAGS are tuned for callgrind:
#    -g3                          full debug info for symbol resolution
#    -O1                          realistic hotspot costs without losing structure
#    -fno-omit-frame-pointer      keep frame pointers so callgrind can stack-walk
#    -fno-inline + -Dalways_inline=
#                                 preserve call edges; -fno-inline alone leaves
#                                 CC_HINT(flatten) and the always_inline attribute
#                                 to still erase them
#    -fno-optimize-sibling-calls  suppress tail-call elimination
#    -fno-plt                     cross-library calls go through the GOT instead
#                                 of PLT stubs, which lack DWARF info
#    -fno-builtin                 keep stdlib helpers (memcpy, strlen, ...) visible
#                                 instead of having them inlined as builtins
#
WORKDIR /usr/local/src/repositories/freeradius-server
COPY . .
# Wipe any host build artefacts that survived the COPY before invoking
# autoconf/make so the container builds from a clean state. The
# libbacktrace submodule in particular tends to carry host-absolute
# paths in its generated Makefile / libtool.
RUN rm -rf build autom4te.cache .libs config.log config.status \
        src/lib/backtrace/Makefile src/lib/backtrace/config.log \
        src/lib/backtrace/config.status src/lib/backtrace/libtool \
        src/lib/backtrace/.libs src/lib/backtrace/*.la \
        src/lib/backtrace/*.lo
#
#  --prefix=/usr puts binaries under /usr/{bin,sbin}, libraries under
#  /usr/lib, etc. so the profiling image's filesystem layout matches
#  the production deb/rpm packages. Test fixtures and scripts can use
#  the same absolute paths (e.g. /usr/bin/radclient) in either mode.
#
RUN ./configure \
        --prefix=/usr \
        --enable-developer \
        --disable-verify-ptr \
        --with-raddbdir=/etc/freeradius \
        CFLAGS="-g3 -O1 -fno-omit-frame-pointer -fno-inline -Dalways_inline= -fno-optimize-sibling-calls -fno-plt -fno-builtin" \
        LDFLAGS="-fno-omit-frame-pointer" \
    && make -j$(nproc) \
    && make install

#
#  Provide `freeradius` / `freeradius.conf` / `/etc/raddb` aliases so
#  profiling scripts and configs match the names used by the production
#  packages.
#
RUN ln -sf /usr/sbin/radiusd /usr/sbin/freeradius \
 && ln -sf /etc/freeradius/radiusd.conf /etc/freeradius/freeradius.conf \
 && ln -sf /etc/freeradius /etc/raddb

#
#  Generate the self-signed RSA (and DH/EC) certificates the test
#  fixtures expect.
#
RUN cd /etc/freeradius/certs && make
