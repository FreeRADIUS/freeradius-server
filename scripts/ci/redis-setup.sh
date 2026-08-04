#!/bin/bash -e

PORT=30000
NODES=6
REPLICAS=1
TLS=0

while getopts 'a:p:n:r:t' opt; do
    case "$opt" in
    a)
	PASSWORD="$OPTARG"
	;;
    p)
        PORT="$OPTARG"
        ;;
    n)
        NODES="$OPTARG"
        ;;
    r)
        REPLICAS="$OPTARG"
        ;;
    t)
	TLS=1
	;;
    esac
done
shift $((OPTIND - 1))

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
    if [ "x$PASSWORD" != "x" ]; then
	echo "AUTH_OPTIONS=\"--masterauth ${PASSWORD} --requirepass ${PASSWORD}\"" >> "${TMP_REDIS_DIR}/config.sh"
	echo "export REDISCLI_AUTH=\"${PASSWORD}\"" >> "${TMP_REDIS_DIR}/config.sh"
    fi
    echo "PORT=$PORT" >> "${TMP_REDIS_DIR}/config.sh"
    echo "NODES=$NODES" >> "${TMP_REDIS_DIR}/config.sh"
    echo "REPLICAS=$REPLICAS" >> "${TMP_REDIS_DIR}/config.sh"

    if [ "$TLS" -eq 1 ]; then
        echo "TLS_OPTIONS=\"--tls-cert-file ${TMP_REDIS_DIR}/tests/tls/redis.crt --tls-key-file ${TMP_REDIS_DIR}/tests/tls/redis.key --tls-ca-cert-file ${TMP_REDIS_DIR}/tests/tls/ca.crt --tls-cluster yes\"" >> "${TMP_REDIS_DIR}/config.sh"
        echo "TLS_CLIENT_OPTIONS=\"--tls --cert ${TMP_REDIS_DIR}/tests/tls/redis.crt --key ${TMP_REDIS_DIR}/tests/tls/redis.key --cacert ${TMP_REDIS_DIR}/tests/tls/ca.crt\"" >> "${TMP_REDIS_DIR}/config.sh"

        sed -ie "s#--port#--port 0 --tls-port#" "${TMP_REDIS_DIR}/create-cluster"
        sed -ie "s#redis-cli#redis-cli \${TLS_CLIENT_OPTIONS}#" "${TMP_REDIS_DIR}/create-cluster"
    fi

    sed -ie "s#\${ADDITIONAL_OPTIONS}#\${ADDITIONAL_OPTIONS} \${AUTH_OPTIONS} \${TLS_OPTIONS}#" "${TMP_REDIS_DIR}/create-cluster"
fi

if [ "$TLS" -eq 1 ]; then
    if [ ! -e "${TMP_REDIS_DIR}/tests/tls " ]; then
        curl https://raw.githubusercontent.com/antirez/redis/unstable/utils/gen-test-certs.sh > "${TMP_REDIS_DIR}/gen-test-certs.sh"
        chmod +x "${TMP_REDIS_DIR}/gen-test-certs.sh"
        gen-test-certs.sh
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
	if [ "$TLS" -eq 1 ]; then
	    source ${TMP_REDIS_DIR}/config.sh
	fi
        waits=0
        STARTPORT=$((PORT+1))
        ENDPORT=$((STARTPORT+NODES))
        for node in {$STARTPORT..$ENDPORT}; do
                while [ $waits -lt 10 ]; do
                        redis-cli ${TLS_CLIENT_OPTIONS} -p $node quit > /dev/null && break
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
