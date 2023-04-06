#!/bin/bash
#
# Simple script blocking requests from proxy to home server
#
#  This works only on Linux.  It can be used to create random networking issues.

if [ $UID -ne 0 ]; then
        echo "Only 'root' can modify 'iptables' rules"
        exit 1
fi

MAXWAIT=5
while true; do
        _wait="$((RANDOM % MAXWAIT))"

        echo "(*) Blocking the port 2083 for ${_wait}s"
        iptables -A INPUT -p tcp --dport 2083 -j REJECT
        sleep $_wait

        echo "(*) Allowing the port 2083 for ${_wait}s"
        iptables -D INPUT -p tcp --dport 2083 -j REJECT
        sleep $_wait
done
