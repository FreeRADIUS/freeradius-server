#!/bin/bash
if ! [ -f "/test/config" ]; then
  echo "No configuration file found, test run incorrectly or docker-compose.yml not set up correctly?"
  exit 1
fi
# Docker generates container names based on the folder that compose is run from, for some god-forsaken reason
compose_dir=$(head -1 "/test/config")
echo "compose_dir: $compose_dir"
log_level=$(tail -1 "/test/config")
echo "log_level: $log_level"

# Unfortunately, our clients do not know their own human readable name as far as I can tell, so the proxy must know their HOSTNAME to have information in common for realms
ls /test/containers | grep realm_ > /client-hostnames.txt

# We will generate the proxy.conf file that will be used in a separate directory
mkdir /eqx
touch /eqx/proxy.conf
cp /test/proxy/radiusd.conf /eqx/radiusd.conf

i=1
while read -r -u 3 c_name
do
  cat /test/proxy/proxy.PART | sed -e "s/##C_NAME##/$c_name/g" -e "s/##H_IP##/$compose_dir-home-$i/g" >> /eqx/proxy.conf
  i=$((i+1))
done 3<"/client-hostnames.txt"

# This file is so the clients know the proxy is starting the server soon; checking at an earlier point is possible to fail if hostname resolution is very slow
touch /test/containers/proxy-running
if [ "$log_level" -eq 1 ]; then
  freeradius -d /eqx -f -l "/test/containers/proxy_server.log"
elif [ "$log_level" -eq 2 ]; then
  freeradius -d /eqx -fx -l "/test/containers/proxy_server.log"
elif [ "$log_level" -eq 3 ]; then
  freeradius -d /eqx -fxx -l "/test/containers/proxy_server.log"
else
  freeradius -d /eqx -f -l stdout
fi
