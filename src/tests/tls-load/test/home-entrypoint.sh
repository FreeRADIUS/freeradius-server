#!/bin/bash
if [ "$LOG_LEVEL" -eq 2 ]; then
  exec /fbin/radiusd -d /test/home -fx -l stdout
elif [ "$LOG_LEVEL" -eq 3 ]; then
  exec /fbin/radiusd -d /test/home -fxx -l stdout
else
  exec /fbin/radiusd -d /test/home -f -l stdout
fi
