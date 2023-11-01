#!/bin/sh
#
#  Auto-create things
#
for i in $(seq 0 255 32); do
  for j in $(seq 1 255); do
    cat <<EOF
10.$i.$j.0/27
	dhcpv4.Router-Address := 10.$i.$j.1,
	dhcpv4.Subnet-Mask := 255.255.255.224

EOF
   done
done
