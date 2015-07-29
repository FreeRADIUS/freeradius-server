#!/bin/sh -e

#
#  If this Travis matrix element does not require the build, we still need to run
#  configure to make sure any autoconf generated files (tls-h et al) are still
#  produced. The top level Make.inc is required for building Debian packages too.
#
if [ "${DO_BUILD}" = 'no' ]; then
    echo "Performing minimal configuration"
    ./configure -C --without-modules
    exit 0
fi

#
#  Configure the server as per the build matrix
#
echo "Performing full configuration"
CFLAGS="${BUILD_CFLAGS}" ./configure -C \
    --enable-werror \
    --prefix=$HOME/freeradius \
    --with-shared-libs=$LIBS_SHARED \
    --with-threads=$LIBS_OPTIONAL \
    --with-udpfromto=$LIBS_OPTIONAL \
    --with-openssl=$LIBS_OPTIONAL \
    --with-pcre=$LIBS_OPTIONAL

#
#  Build the server
#
echo "Starting compilation"
make -j8

#
#  If this is not a Coverity build (which would duplicate the parameters of another build)
#  and we're building with clang, run the clang scanner over the source.
#
if [ "${COVERITY_SCAN_BRANCH}" != 1 -a ${CC} = 'clang' ]; then
    echo "Starting clang scan"
    make -j8 scan && [ "$(find build/plist/ -name *.html)" = '' ];
fi

#
#  Setup fixtures for the 'script' phase
#
echo "Setting up fixtures"
./scripts/travis/postgresql-setup.sh
./scripts/travis/mysql-setup.sh
./scripts/travis/ldap-setup.sh
# Travis doesn't have Redis 3.0 available yet
# ./scripts/travis/redis-setup.sh
