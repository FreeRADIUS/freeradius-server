#!/bin/bash -e

PORT=21000
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

# Each cluster keeps its own state, so two clusters on different base ports
# can run at the same time.
TMP_REDIS_DIR="/tmp/redis-${PORT}"

# The script changes directory below, so recursive calls need the full path.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
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
    if [ -e /usr/local/bin/redis-create-cluster ]; then
        #  The CI images bake a copy in, so no test-time download is needed.
        cp /usr/local/bin/redis-create-cluster "${TMP_REDIS_DIR}/create-cluster"
        chmod +x "${TMP_REDIS_DIR}/create-cluster"
    else
        #  Download to a temporary name and move into place on success only.
        #  A failed download must not leave an empty create-cluster behind,
        #  because the file's existence is what skips this block next run.
        curl -f -o "${TMP_REDIS_DIR}/create-cluster.dl" https://raw.githubusercontent.com/redis/redis/unstable/utils/create-cluster/create-cluster
        chmod +x "${TMP_REDIS_DIR}/create-cluster.dl"
        mv "${TMP_REDIS_DIR}/create-cluster.dl" "${TMP_REDIS_DIR}/create-cluster"
    fi

    # Masters delay the first replica sync by repl-diskless-sync-delay
    # (5s by default) to batch replicas up, and with retries a replica can
    # take tens of seconds to hold any data.  The tests wait on replicas,
    # so sync immediately.
    echo "ADDITIONAL_OPTIONS=\"--repl-diskless-sync-delay 0\"" > "${TMP_REDIS_DIR}/config.sh"

    # redis versions greater than 7 need --enable-debug-command local passed otherwise
    # they don't allow access to the debug commands we use in tests.
    if [ "${REDIS_MAJOR_VERSION}" -ge 7 ]; then
        echo "ADDITIONAL_OPTIONS=\"\${ADDITIONAL_OPTIONS} --enable-debug-command local\"" >> "${TMP_REDIS_DIR}/config.sh"
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

#
#  Reset for the next test.  A healthy cluster only needs its data flushed,
#  which takes milliseconds.  A cluster with a dead node (the node_fail test
#  kills one) or no cluster at all needs the full rebuild.
#
if [ "$1" == "reset" ] || [ "$1" == "rebuild" ]; then
    if [ -f "${TMP_REDIS_DIR}/config.sh" ]; then
        source "${TMP_REDIS_DIR}/config.sh"
    fi
    healthy=1
    if [ "$1" == "rebuild" ]; then
        healthy=0
    fi
    STARTPORT=$((PORT+1))
    ENDPORT=$((PORT+NODES))
    for node in $(seq $STARTPORT $ENDPORT); do
        if [ "$(redis-cli ${TLS_CLIENT_OPTIONS} -p $node ping 2>/dev/null)" != "PONG" ]; then
            healthy=0
            break
        fi
    done
    if [ "$healthy" -eq 1 ] && ! redis-cli ${TLS_CLIENT_OPTIONS} -p $STARTPORT cluster info 2>/dev/null | grep -q 'cluster_state:ok'; then
        healthy=0
    fi
    if [ "$healthy" -eq 1 ]; then
        # Replicas refuse FLUSHALL and inherit the flush from their master.
        for node in $(seq $STARTPORT $ENDPORT); do
            redis-cli ${TLS_CLIENT_OPTIONS} -p $node FLUSHALL > /dev/null 2>&1 || true
        done
        echo "flushed"
        exit 0
    fi
    "$SELF" -p "$PORT" stop
    "$SELF" -p "$PORT" clean
    "$SELF" -p "$PORT" start
    "$SELF" -p "$PORT" create

    #  create returns before the nodes agree on the cluster state, and a
    #  cluster answering cluster_state:fail fails every command sent to it,
    #  so wait until every node reports the cluster is usable.
    for i in $(seq 1 40); do
        converged=1
        for node in $(seq $STARTPORT $ENDPORT); do
            if ! redis-cli ${TLS_CLIENT_OPTIONS} -p $node cluster info 2>/dev/null | grep -q 'cluster_state:ok'; then
                converged=0
                break
            fi
        done
        if [ "$converged" -eq 1 ]; then
            exit 0
        fi
        sleep 0.5
    done
    echo "Gave up waiting for the cluster on port $PORT to converge" >&2
    exit 1
fi

# Ensure all nodes are accessible before creating cluster
if [ "$1" == "create" ]; then
	if [ "$TLS" -eq 1 ]; then
	    source ${TMP_REDIS_DIR}/config.sh
	fi
        STARTPORT=$((PORT+1))
        ENDPORT=$((PORT+NODES))
        for node in $(seq $STARTPORT $ENDPORT); do
                waits=0
                until redis-cli ${TLS_CLIENT_OPTIONS} -p $node quit > /dev/null 2>&1; do
                        #  Parallel test suites start several clusters at
                        #  once, and a node has taken over five seconds to
                        #  accept connections under that load.
                        if [ $waits -ge 120 ]; then
                                echo "Giving up on cluster create: node on port $node did not accept connections within 60 seconds" >&2
                                echo "NODE LOG: ${TMP_REDIS_DIR}/${node}.log" >&2
                                cat "${TMP_REDIS_DIR}/${node}.log" >&2 || true
                                exit 1
                        fi
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
