#!/bin/sh
#
#	Let's see if exist '$expected' entries of "$test_regex" in ${test_in}
#

test_in="build/tests/radclient/acct_3.out"
sent=$(grep "Sent Accounting-Request" ${test_in} | wc -l)
recv=$(grep "Received Accounting-Response" ${test_in} | wc -l)

expected=7

if [ $sent -ne $expected ]; then
	echo "ERROR: We expected ${expected} 'Sent Accounting-Request' in '${test_in}, got ${sent}'"
	exit 1
fi

if [ $sent -ne $expected ]; then
	echo "ERROR: We expected ${expected} entries of 'Received Accounting-Response' in '${test_in}, got ${recv}'"
	exit 1
fi
