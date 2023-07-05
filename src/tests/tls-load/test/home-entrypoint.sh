#!/bin/bash
umask 002
if [ "$LOG_LEVEL" -eq 1 ]; then
  exec freeradius -d /test/home -f -l "/test/containers/home_server_$HOSTNAME.log"
elif [ "$LOG_LEVEL" -eq 2 ]; then
  exec freeradius -d /test/home -fx -l "/test/containers/home_server_$HOSTNAME.log"
elif [ "$LOG_LEVEL" -eq 3 ]; then
  exec freeradius -d /test/home -fxx -l "/test/containers/home_server_$HOSTNAME.log"
else
  exec freeradius -d /test/home -f -l stdout
fi
