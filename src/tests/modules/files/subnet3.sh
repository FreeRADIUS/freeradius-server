#!/bin/sh
#
#  Auto-create things
#
for i in $(seq 0 255 32); do
  for j in $(seq 1 255); do
    cat <<EOF
10.$i.$j.0/27
	Framed-IP-Address := 10.$i.$j.1,
	PMIP6-Home-IPv4-HoA := 10.$i.$j.2/27,
	Class := 0xabcdef

EOF
   done
done
