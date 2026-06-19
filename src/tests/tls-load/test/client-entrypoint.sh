#!/bin/bash
touch /test/containers/realm_"$HOSTNAME"
# Unfortunately, I don't really know a better way to synchronize the clients than a short sleep length 
# and a sufficient number of requests.
# It still seems like sometimes one can start inordinately later than the others.
while ! [ -f "/test/containers/proxy-running" ]; do
  sleep 0.1
done
rm /test/containers/realm_"$HOSTNAME"
echo User-Name="bob@realm_$HOSTNAME",User-Password="bob",Message-Authenticator=0x00 | /fbin/radclient -c "$NUM_REQUESTS" test-container-proxy-1 auth testing123
if [ "$?" -ne 0 ] ; then
  echo "This container failed"
  exit 1
else
  echo "This container succeeded"
fi
