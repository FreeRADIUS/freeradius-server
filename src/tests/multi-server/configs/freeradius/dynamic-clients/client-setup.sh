#!/bin/bash
#
#  Entrypoint of the client container.  Each case sends from an address of
#  the client that the server has not seen, so the script adds one alias
#  per case to the interface of the container, then keeps the container
#  alive.  `CLIENT_ADDRESSES` holds the last octet of each alias, space
#  separated, and `send.sh --source <octet>` binds radclient to the alias
#  that ends in that octet.
#
#  The service image ships without iproute2, so the script installs
#  iproute2 first, the way env-setup.sh does for the kafka environment.
#  The script touches /run/client-ready when the aliases are in place, and
#  the compose healthcheck of the container tests for that file, so the
#  servers start only once the client can send from every alias.
#
set -eu

apt-get -qq update
apt-get -qq install -y --no-install-recommends iproute2 > /dev/null

own=$(ip -4 -o addr show dev eth0 | head -1 | awk '{print $4}' | cut -d/ -f1)
for octet in $CLIENT_ADDRESSES; do
	ip addr add "${own%.*}.${octet}/32" dev eth0
done

touch /run/client-ready
exec sleep infinity
