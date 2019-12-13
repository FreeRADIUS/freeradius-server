#!/bin/sh
set -e

#
#  Add docker subnet as a known client.
#
CLIENT_ADDR="${CLIENT_ADDR:-172.17.0.0/16}"
CLIENT_SECRET="${CLIENT_SECRET:-testing123}"

cat >> /etc/freeradius/clients.conf <<EOF

#
#  Docker interface
#
client docker_client01 {
	ipaddr = ${CLIENT_ADDR}
	secret = ${CLIENT_SECRET}
}
EOF

# this if will check if the first argument is a flag
# but only works if all arguments require a hyphenated flag
# -v; -SL; -f arg; etc will work, but not arg1 arg2
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    set -- freeradius "$@"
fi

# check for the expected command
if [ "$1" = 'freeradius' ]; then
    shift
    exec freeradius -f "$@"
fi

# many people are likely to call "radiusd" as well, so allow that
if [ "$1" = 'radiusd' ]; then
    shift
    exec freeradius -f "$@"
fi

# else default to run whatever the user wanted like "bash" or "sh"
exec "$@"
