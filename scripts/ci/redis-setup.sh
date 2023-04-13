#!/bin/bash -e

TMP_REDIS_DIR='/tmp/redis'
REDIS_MAJOR_VERSION="$(redis-server -v | grep -o 'v=[0-9.]*' | cut -d= -f2 | cut -d. -f1)"

export PATH="${TMP_REDIS_DIR}:${PATH}"

if [ ! -e "${TMP_REDIS_DIR}" ]; then
    mkdir -p "${TMP_REDIS_DIR}"
fi

if [ "$(which redis-server)" = '' ]; then
    echo "Can't find redis-server (sudo apt-get install redis, brew install redis etc...)"
    exit 1
fi

# The various Redis setup scripts and instances put their data here
cd "${TMP_REDIS_DIR}"

# Download the latest versions of the cluster test utilities
# these are only available via the Redis repo, and it seems more sensible to download
# two short scripts, than to maintain a local copy, or clone the whole repo.
if [ ! -e "${TMP_REDIS_DIR}/create-cluster" ]; then
    curl https://raw.githubusercontent.com/antirez/redis/unstable/utils/create-cluster/create-cluster > "${TMP_REDIS_DIR}/create-cluster"
    chmod +x "${TMP_REDIS_DIR}/create-cluster"

    # redis versions greater than 7 need --enable-debug-command local passed otherwise
    # they don't allow access to the debug commands we use in tests.
    if [ "${REDIS_MAJOR_VERSION}" -ge 7 ]; then
        echo "ADDITIONAL_OPTIONS=\"--enable-debug-command local\"" > "${TMP_REDIS_DIR}/config.sh"
    fi
fi

# Fix hardcoded paths in the test script
sed -ie "s#\$BIN_PATH/redis-cli#echo 'yes' | redis-cli#" "${TMP_REDIS_DIR}/create-cluster"
sed -ie "s#\$BIN_PATH/redis-server#redis-server#" "${TMP_REDIS_DIR}/create-cluster"

# appenddirname was added in v7 and triggers errors if passed to older versions
if [ "${REDIS_MAJOR_VERSION}" -lt 7 ]; then
    sed -ie "s# --appenddirname appendonlydir-\${PORT}##" "${TMP_REDIS_DIR}/create-cluster"
    # Fix cleanup to match option change above
    sed -ie "s#appendonlydir-\*#appendonly\*.aof#" "${TMP_REDIS_DIR}/create-cluster"
fi

# Ensure all nodes are accessible before creating cluster
if [ "$1" == "create" ]; then
        waits=0
        for node in 30001 30002 30003 30004 30005 30006; do
                while [ $waits -lt 10 ]; do
                        redis-cli -p $node quit > /dev/null && break
                        sleep 0.5
                        waits=$((waits + 1))
                done
        done
fi

# Again, not needed for CI, but useful for local testing
if [ -z "$1" ]; then
    create-cluster start
    create-cluster create
    echo "Run \"$0 stop && $0 clean\" to cleanup"
else
    create-cluster $1
fi
