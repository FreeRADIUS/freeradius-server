#
#  Build and install FreeRADIUS with profiling-friendly CFLAGS into the
#  profiling image. Layered on top of the crossbuild base, which already
#  provides build deps and a clone of the upstream source at
#  /usr/local/src/repositories/freeradius-server. The local checkout is
#  copied in over the top so the image reflects the branch under test,
#  not whatever was on upstream master at image build time.
#
#  CFLAGS used here are tuned for callgrind: -g3 for full debug info,
#  -O1 for realistic hotspot costs, and -fno-inline / -Dalways_inline= /
#  -fno-plt / -fno-builtin / -fno-optimize-sibling-calls / -fno-omit-frame-pointer
#  to keep the call graph aligned with the source. Inlined or tail-called
#  frames are otherwise lost in the callgrind output.
#
WORKDIR /usr/local/src/repositories/freeradius-server
COPY . .
RUN ./configure \
        --enable-developer \
        --disable-verify-ptr \
        --with-raddbdir=/etc/freeradius \
        CFLAGS="-g3 -O1 -fno-omit-frame-pointer -fno-inline -Dalways_inline= -fno-plt -fno-builtin -fno-optimize-sibling-calls" \
        LDFLAGS="-fno-omit-frame-pointer" \
    && make -j$(nproc) \
    && make install

#
#  Provide `freeradius` / `freeradius.conf` / `/etc/raddb` aliases so
#  profiling scripts and configs match the names used by the production
#  packages.
#
RUN ln -sf /usr/local/sbin/radiusd /usr/local/sbin/freeradius \
 && ln -sf /etc/freeradius/radiusd.conf /etc/freeradius/freeradius.conf \
 && ln -sf /etc/freeradius /etc/raddb

#
#  Generate the self-signed RSA (and DH/EC) certificates the test
#  fixtures expect.
#
RUN cd /etc/freeradius/certs && make
