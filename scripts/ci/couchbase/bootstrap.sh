#!/bin/bash
# Author: Jorge Pereira <jpereira@freeradius.org>
# All the 'sleep' calls are necessary to wait the couchbased
# service complete the processs.
#

couchbase_host="localhost"
couchbase_user="radius"
couchbase_pass="radius"
couchbase_bucket="radius"

_cbimport() {
  view=$1
  index=$2
  file=$3

  cbimport json --format list -c "$couchbase_host" -u "$couchbase_user" -p "$couchbase_pass" -b "$couchbase_bucket" \
    -d "file://$file" --scope-collection-exp "_default._default" -g "$index"
}

#set -fx

#
# 1. Reset docker couchbase
#
docker rm -f couchbase
docker run -d --name couchbase -p 8091-8094:8091-8094 -p 11210:11210 couchbase/server
sleep 5

#
# 2. Initialize the node
#

# Set up services. (Note that %2C is the ASCII Hex mapping to the comma character.)
curl -s -X POST -u "${couchbase_user}:${couchbase_pass}" "http://${couchbase_host}:8091/node/controller/setupServices" -d 'services=kv%2Cn1ql%2Cindex%2Cfts'
sleep 5

# Initialize a node. (Note that %2F is the ASCII Hex mapping to the forward-slash character.)
curl -s -X POST "http://${couchbase_host}:8091/nodes/self/controller/settings" -d 'path=%2Fopt%2Fcouchbase%2Fvar%2Flib%2Fcouchbase%2Fdata&index_path=%2Fopt%2Fcouchbase%2Fvar%2Flib%2Fcouchbase%2Fdata'
sleep 2

# Set up your administrator-username and password.
curl -s -X POST "http://${couchbase_host}:8091/settings/web" -d "password=${couchbase_pass}&username=${couchbase_user}&port=8091"

# Set up the index RAM quota (to be applied across the entire cluster).
curl -s -X POST -u "${couchbase_user}:${couchbase_pass}" "http://${couchbase_host}:8091/pools/default" -d 'memoryQuota=256' -d 'indexMemoryQuota=256'

# 3. create bucket
echo "# Create Bucket: $couchbase_bucket"
curl -s -X POST -u "${couchbase_user}:${couchbase_pass}" http://${couchbase_host}:8091/pools/default/buckets \
			-d "name=${couchbase_bucket}" -d "bucketType=couchbase" -d "ramQuotaMB=256"
sleep 1

# 4. create views
echo "# Create 'client' view"
curl -s -X PUT -u "${couchbase_user}:${couchbase_pass}" -H 'Content-Type: application/json' "http://${couchbase_host}:8092/${couchbase_bucket}/_design/client" \
			-d @data/client.view.json
sleep 2

# 5.
echo "# Import Clients"
_cbimport "/${couchbase_bucket}/_design/client" "%clientIdentifier%" "data/client.load.json"

# 6. Import "raduser" sample
echo "# Import 'raduser' sample for 'bob'"
_cbimport "/${couchbase_bucket}/_design/raduser" "raduser_%userName%" "data/authorize_raduser.load.json"
