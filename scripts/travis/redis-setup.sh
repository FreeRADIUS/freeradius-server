#!/bin/bash -e

TMP_REDIS_DIR='/tmp/redis'
export PATH="${TMP_REDIS_DIR}:${PATH}"

if [ ! -e "${TMP_REDIS_DIR}" ]; then
    mkdir -p "${TMP_REDIS_DIR}"
fi

if [ ! -e "${TMP_REDIS_DIR}/cluster" ]; then
    mkdir -p "${TMP_REDIS_DIR}/cluster"
fi

if [ "$(which redis-server)" = '' ]; then
    echo "Can't find redis-server (sudo apt-get install redis, brew install redis etc...)"
    exit 1
fi

# The various Redis setup scripts and instances put their data here
cd "${TMP_REDIS_DIR}/cluster"

# Download the latest versions of the cluster test utilities
# these are only available via the Redis repo, and it seems more sensible to download
# two short scripts, than to maintain a local copy, or clone the whole repo.
if [ ! -e "${TMP_REDIS_DIR}/create-cluster" ]; then
    curl https://raw.githubusercontent.com/antirez/redis/unstable/utils/create-cluster/create-cluster > "${TMP_REDIS_DIR}/create-cluster"
    chmod +x "${TMP_REDIS_DIR}/create-cluster"
fi

# Fix hardcoded paths in the test script
sed -ie "s#../../src/redis-trib.rb#${TMP_REDIS_DIR}/redis-trib.rb#" "${TMP_REDIS_DIR}/create-cluster"
sed -ie "s#../../src/##" "${TMP_REDIS_DIR}/create-cluster"

if [ ! -e "${TMP_REDIS_DIR}/redis-trib.rb" ]; then
    curl https://raw.githubusercontent.com/antirez/redis/unstable/src/redis-trib.rb > "${TMP_REDIS_DIR}/redis-trib.rb"
    chmod +x "${TMP_REDIS_DIR}/redis-trib.rb"
fi

# Make redis-trib non interactive
sed -ie 's/yes_or_die "\(.*\)"/xputs "\1 Yes!"/' "${TMP_REDIS_DIR}/redis-trib.rb"

# Install the 'redis' gem (needed for redis-trib) - not actually needed by travis
# but is useful if we're running redis-setup.sh locally.
if [ `gem list redis -i` = 'false' ]; then
    gem install redis
fi

# Again, not needed by travis, but useful for local testing
if [ "$1" = 'stop' ]; then
    create-cluster stop
    create-cluster clean
else
    create-cluster start
    create-cluster create
    echo "Run \"$0 stop\" to cleanup"
fi
