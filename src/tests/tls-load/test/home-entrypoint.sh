#!/bin/bash
if ! [ -f "/test/config" ]; then
  echo "No configuration file found, test run incorrectly or docker-compose.yml not set up correctly?"
  exit 1
fi
log_level=$(tail -1 "/test/config")
echo "log_level: $log_level"
if [ "$log_level" -eq 1 ]; then
  freeradius -d /test/home -f -l "/test/containers/home_server_$HOSTNAME.log"
elif [ "$log_level" -eq 2 ]; then
  freeradius -d /test/home -fx -l "/test/containers/home_server_$HOSTNAME.log"
elif [ "$log_level" -eq 3 ]; then
  freeradius -d /test/home -fxx -l "/test/containers/home_server_$HOSTNAME.log"
else
  freeradius -d /test/home -f -l stdout
fi
