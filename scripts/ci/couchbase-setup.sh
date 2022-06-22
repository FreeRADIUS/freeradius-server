#!/bin/bash
# Author: Jorge Pereira <jorge@freeradius.org>
# Magical script to bootstrap the Couchbase server.
#

couchbase_host="${COUCHBASE_TEST_SERVER:-localhost}"
couchbase_user="radius"
couchbase_pass="radius"
couchbase_bucket="radius"

UNAME_S=$(uname -s)
case $UNAME_S in
  Linux)
    if ! [ -e "/opt/couchbase/bin/couchbase-server" ]; then
        echo "Can't find couchbase-server (sudo apt-get install couchbase-server-community={version})"
        exit 1
    fi

    export PATH="/opt/couchbase/bin:$PATH"
    ;;

  Darwin)
    if ! [ -e "/Applications/Couchbase Server.app" ]; then
        echo "Can't find couchbase-server (brew install couchbase-server-community etc...)"
        exit 1
    fi

    export PATH="/Applications/Couchbase Server.app/Contents/Resources/couchbase-core/bin:$PATH"
  ;;

  *)
    echo "ERROR: Unknown $UNAME_S system"
    exit 1
esac

_cbimport() {
  view=$1
  index=$2
  file=$3

  cbimport json --format list -c "$couchbase_host" -u "$couchbase_user" -p "$couchbase_pass" -b "$couchbase_bucket" \
    -d "file://$file" --scope-collection-exp "_default._default" -g "$index"
}

curl_run() {
  local _method="$1"
  local _url="$2"
  shift 2
  local _args="$@"

  local _i=1

  while true; do
    code=$(curl ${CURL_OPTS} -s -o /dev/null -w "%{http_code}" -X "${_method}" -u "${couchbase_user}:${couchbase_pass}" "${_url}" ${_args[*]})

    case $code in
      000*)
          echo "$0: ERROR: The host ${_url} is down. exiting."
          exit 1
        ;;
      200*|201*|400*) break;;
    esac

    if [ $((_i % 10 )) -eq 0 ]; then # print out only each 1s
      echo "$0: WARN[${_i}]: Got $code http code from '${_url}'. let's try again!"
      CURL_OPTS="-v"
    fi

    let "_i+=1"

    sleep 0.1 # wait for 100ms
  done
}

# Set up services. (Note that %2C is the ASCII Hex mapping to the comma character.)
curl_run "POST" "http://${couchbase_host}:8091/node/controller/setupServices" \
      -d "services=kv,n1ql,index,fts"

# Initialize a node. (Note that %2F is the ASCII Hex mapping to the forward-slash character.)
curl_run "POST" "http://${couchbase_host}:8091/nodes/self/controller/settings" \
      -d "path=/opt/couchbase/var/lib/couchbase/data&index_path=/opt/couchbase/var/lib/couchbase/data"

# Set up your administrator-username and password.
curl_run "POST" "http://${couchbase_host}:8091/settings/web" \
      -d "password=${couchbase_pass}&username=${couchbase_user}&port=8091"

# Set up the index RAM quota (to be applied across the entire cluster).
curl_run "POST" "http://${couchbase_host}:8091/pools/default" \
      -d "memoryQuota=256" -d "indexMemoryQuota=256"

# ... FreeRADIUS setup
# Create Bucket: $couchbase_bucket
curl_run "POST" "http://${couchbase_host}:8091/pools/default/buckets" \
      -d "name=${couchbase_bucket}" -d "bucketType=couchbase" -d "ramQuotaMB=256"

curl_run "PUT" "http://${couchbase_host}:8092/${couchbase_bucket}/_design/client" -H "Content-Type:application/json" -i \
      -d @scripts/ci/couchbase/data/client.view.json

echo "# Import Clients"
_cbimport "/${couchbase_bucket}/_design/client" "%clientIdentifier%" "scripts/ci/couchbase/data/client.load.json"

echo "# Import 'raduser' sample for 'bob'"
_cbimport "/${couchbase_bucket}/_design/raduser" "raduser_%userName%" "scripts/ci/couchbase/data/authorize_raduser.load.json"
