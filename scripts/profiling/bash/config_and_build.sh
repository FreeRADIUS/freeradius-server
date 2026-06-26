#!/bin/bash
#
# Configure and build FreeRADIUS with profiling-friendly compiler flags.
#
# Usage: config_and_build.sh --fr_src_dir <dir>
#
#   --fr_src_dir  Root of the FreeRADIUS source tree. ./configure and make
#                 are run from this directory.
#
# Run this from inside the freeradius4-profiling-deps container with the
# source tree mounted at <dir>.

set -x

fr_src_dir=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fr_src_dir)
            fr_src_dir="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$fr_src_dir" ]]; then
    echo "Usage: $0 --fr_src_dir <dir>" >&2
    exit 1
fi

cd "${fr_src_dir}"

./configure \
  --enable-developer \
  --disable-verify-ptr \
  CFLAGS="-g3 -O1 -fno-omit-frame-pointer -fno-inline -Dalways_inline= -fno-optimize-sibling-calls -fno-plt -fno-builtin" \
  LDFLAGS="-fno-omit-frame-pointer"

# Build server
make -j$(nproc)

# Clean up certs to make sure old ones are removed and doesn't cause issues
# Generate new certs
cd ${fr_src_dir}/raddb/certs && make distclean && cd ${fr_src_dir} && make certs

