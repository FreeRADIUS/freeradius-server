#!/bin/sh
#
#	Let's see if exist '$expected' entries of "$test_regex" in ${test_in}
#

test_in="build/tests/radclient/auth_3.out"
sent=$(grep "Sent Access-Request" ${test_in} | wc -l)
recv=$(grep "Received Access-Accept" ${test_in} | wc -l)

expected=5

if [ $sent -ne $expected ]; then
	echo "ERROR: We expected ${expected} 'Sent Access-Request' in '${test_in}, got ${sent}'"
	exit 1
fi

if [ $sent -ne $expected ]; then
	echo "ERROR: We expected ${expected} entries of 'Received Access-Accept' in '${test_in}, got ${recv}'"
	exit 1
fi
