#!/bin/bash

# Unfortunately, our clients do not know their own human readable name as far as I can tell, so the proxy must know their HOSTNAME to have information in common for realms
ls /test/containers | grep realm_ > /client-hostnames.txt

# We will generate the proxy.conf file that will be used in a separate directory
mkdir /eqx
touch /eqx/proxy.conf
cp /test/proxy/radiusd.conf /eqx/radiusd.conf

i=1
while read -r -u 3 c_name
do
  cat /test/proxy/proxy.PART | sed -e "s/##C_NAME##/$c_name/g" -e "s/##H_IP##/test-container-home-$i/g" >> /eqx/proxy.conf
  i=$((i+1))
done 3<"/client-hostnames.txt"

# This file is so the clients know the proxy is starting the server soon; checking at an earlier point is possible to fail if hostname resolution is very slow
touch /test/containers/proxy-running
if [ "$LOG_LEVEL" -eq 2 ]; then
  exec /fbin/radiusd -d /eqx -fx -l stdout
elif [ "$LOG_LEVEL" -eq 3 ]; then
  exec /fbin/radiusd -d /eqx -fxx -l stdout
else
  exec /fbin/radiusd -d /eqx -f -l stdout
fi
