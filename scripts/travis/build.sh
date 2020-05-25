#!/bin/sh -e

enable_llvm_address_sanitizer=""

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
#  Enable address sanitizer for the clang builds
#
if $CC -v 2>&1 | grep clang > /dev/null; then
    echo "Enabling address sanitizer"
    enable_address_sanitizer="--enable-llvm-address-sanitizer"
else
    enable_address_sanitizer=""
fi

#
#  Configure the server as per the build matrix
#
#  We specify -with-rlm-python-bin because Otherwise travis picks up
#  /opt/python, which doesn't have .so available
#
echo "Performing full configuration"
CFLAGS="${BUILD_CFLAGS}" ./configure -C \
    --enable-werror \
    $enable_address_sanitizer \
    --prefix=$HOME/freeradius \
    --with-shared-libs=$LIBS_SHARED \
    --with-threads=$LIBS_OPTIONAL \
    --with-udpfromto=$LIBS_OPTIONAL \
    --with-openssl=$LIBS_OPTIONAL \
    --with-pcre=$LIBS_OPTIONAL \
    --with-rlm-python-bin=/usr/bin/python2.7 \
|| cat ./config.log

echo "Contents of src/include/autoconf.h"
cat "./src/include/autoconf.h"

#
#  Build the server
#
echo "Starting compilation"
make -j8

#
#  If this is not a Coverity build (which would duplicate the parameters of another build)
#  and we're building with clang, run the clang scanner over the source.
#
if [ "${COVERITY_SCAN_BRANCH}" != 1 -a "${CC}" = 'clang' ]; then
    echo "Starting clang scan"
    # Travis only has two cores
    make -j2 scan && [ "$(find build/plist/ -name *.html)" = '' ];
fi

#
#  Setup fixtures for the 'script' phase
#
echo "Setting up fixtures"
./scripts/travis/postgresql-setup.sh
./scripts/travis/mysql-setup.sh
./scripts/travis/ldap-setup.sh
./scripts/travis/redis-setup.sh
