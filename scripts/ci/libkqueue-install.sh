#!/bin/bash -e
# Author: Jorge Pereira <jpereira@freeradius.org>
#

LIBKQUEUE_PATH_SRC="/usr/local/src/repositories/libkqueue.git"
LIBKQUEUE_GITREPO="${LIBKQUEUE_GITREPO:-https://github.com/mheily/libkqueue.git}"
LIBKQUEUE_BRANCH="${LIBKQUEUE_BRANCH:-master}"

BUILD_TYPE="${BUILD_TYPE:-RelWithDebInfo}"
CC="${CC:-clang}"

function fatal() {
    echo "$0: ERROR: $@"
    exit 1
}

if [[ ! "${BUILD_TYPE}" =~ Debug|Release|RelWithDebInfo ]]; then
    fatal "The 'BUILD_TYPE' should be 'Debug' or 'Release'."
fi

echo "# Generating libkqueue: repo=${LIBKQUEUE_GITREPO} branch=${LIBKQUEUE_BRANCH} build_type=${BUILD_TYPE} mode."

#
#  reset
#
rm -rf "${LIBKQUEUE_PATH_SRC}"
mkdir -p /usr/local/src/repositories/
git clone --branch "${LIBKQUEUE_BRANCH}" --depth=1 "${LIBKQUEUE_GITREPO}" "${LIBKQUEUE_PATH_SRC}"
echo "# Last commit"
pushd "${LIBKQUEUE_PATH_SRC}"
git log -1

#
#  Generate the makefiles
#
if ! cmake . -G "Unix Makefiles" \
            -DCMAKE_INSTALL_PREFIX="/usr" \
            -DCMAKE_INSTALL_LIBDIR="lib"  \
            -DCMAKE_VERBOSE_MAKEFILE:BOOL="ON" \
            -DENABLE_TESTING="YES" \
            -DENABLE_ASAN="${ENABLE_ASAN:-NO}" \
            -DENABLE_LSAN="${ENABLE_LSAN:-NO}" \
            -DENABLE_UBSAN="${ENABLE_UBSAN:-NO}" \
            -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"; then
    fatal "Failed during cmake build configuration"
fi

#
#  Build the libkqueue
#
echo "Starting compilation"
if ! make -j8; then
    fatal "Failed during compilation"
fi

#
#  Build the *.deb packages
#
if ! cpack -G DEB; then
    fatal "Failed when building debian packages"
fi

#
#  Installing the *.deb
#
if ! dpkg -i ./lib*.deb; then
	fatal "Failed during installation"
fi
