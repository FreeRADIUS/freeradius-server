#!/bin/bash
echo /etc/freeradius/lib/local/.libs >> /etc/ld.so.conf
ldconfig
if [ "$LOG_LEVEL" -eq 2 ]; then
  exec /etc/freeradius/bin/local/radiusd -D /dict -d /test/home -fx -l stdout
elif [ "$LOG_LEVEL" -eq 3 ]; then
  exec /etc/freeradius/bin/local/radiusd -D /dict -d /test/home -fxx -l stdout
else
  exec /etc/freeradius/bin/local/radiusd -D /dict -d /test/home -f -l stdout
fi
