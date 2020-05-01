#!/bin/sh
#
#	Let's see if exist '$expected' entries of "$test_regex" in ${test_in}
#

test_in="build/tests/radclient/acct_3.out"
test_regex="^\(Received\|Sent\) \(Accounting-Response\|Accounting-Request\)"

entries=$(grep "${test_regex}" ${test_in} | wc -l)
expected=14

if [ $entries -ne $expected ]; then
	echo "ERROR: We expected ${expected} entries of '${test_regex}' in '${test_in}'"
	exit 1
fi
