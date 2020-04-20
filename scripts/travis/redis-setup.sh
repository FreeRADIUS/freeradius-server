#!/bin/sh

set -eu

TMP_REDIS_DIR="${TMP_REDIS_DIR:-/tmp/redis/cluster}"

mkdir -p "${TMP_REDIS_DIR}"

redis-server -v >/dev/null 2>/dev/null || {
    echo "Can't find redis-server (sudo apt-get install redis, brew install redis etc...)"
    exit 1
}

# The various Redis setup scripts and instances put their data here
cd "${TMP_REDIS_DIR}"

# Download the latest versions of the cluster test utilities
# these are only available via the Redis repo, and it seems more sensible to download
# two short scripts, than to maintain a local copy, or clone the whole repo.
if [ ! -x create-cluster ]; then
    curl -f -o create-cluster https://raw.githubusercontent.com/antirez/redis/f95a88d988ffae6901fc186e780c64b747ab5a74/utils/create-cluster/create-cluster

    # Fix hardcoded paths in the test script
    sed -i -e '/BIN_PATH=/ d; s#$BIN_PATH/##' create-cluster

    chmod +x create-cluster
fi

# Again, not needed by travis, but useful for local testing
if [ $# -eq 0 ]; then
    ./create-cluster stop >/dev/null || true
    ./create-cluster clean >/dev/null || true
    ./create-cluster start >/dev/null </dev/null
    echo yes | ./create-cluster create >/dev/null
    echo "Run (inside '${TMP_REDIS_DIR}') \"$0 stop && $0 clean\" to cleanup"
else
    ./create-cluster "$@"
fi

exit 0
