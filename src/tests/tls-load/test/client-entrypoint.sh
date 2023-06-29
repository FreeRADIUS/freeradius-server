#!/bin/bash
if ! [ -f "/test/config" ]; then
  echo "There is no /test directory (specifically the /test/config file) connected to the docker image, test run incorrectly or docker-compose.yml not set up correctly?"
  exit 1
fi
compose_dir=$(head -1 "/test/config")
num_requests=$(tail +2 "/test/config" | head -1)
echo "num_requests: $num_requests"
touch /test/containers/realm_"$HOSTNAME"
# Unfortunately, I don't really know a better way to synchronize the clients than a short sleep length 
# and a sufficient number of requests.
# It still seems like sometimes one can start inordinately later than the others.
while ! [ -f "/test/containers/proxy-running" ]; do
  sleep 0.1
done
rm /test/containers/realm_"$HOSTNAME"
echo User-Name="bob@realm_$HOSTNAME",User-Password="bob",Message-Authenticator=0x00 | radclient -c "$num_requests" "$compose_dir"-proxy-1 auth testing123 > "/test/containers/client_$HOSTNAME.log"
if [ "$?" -ne 0 ] ; then
  echo "This container failed"
  exit 1
else
  echo "This container succeeded"
fi
