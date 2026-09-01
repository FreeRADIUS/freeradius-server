#
#  Include from Redis cluster tests to get clusters back into a known state
#
string clusterctrl
string clusterport
string redisserver
string data1
string data2
string data3
string cmdresult

data1 := "1-%str.rand('aaaaaaaa')"
data2 := "2-%str.rand('aaaaaaaa')"
data3 := "3-%str.rand('aaaaaaaa')"

if ("$ENV{REDIS_CLUSTER_CONTROL}" == '') {
	clusterctrl := 'scripts/ci/redis-setup.sh'
} else {
	clusterctrl := "$ENV{REDIS_CLUSTER_CONTROL}"
}

#
#  Each test suite has a cluster of its own, told apart by base port.
#
clusterport := "$ENV{REDIS_CLUSTER_PORT}"
if (clusterport == '') {
	clusterport := '21000'
}

# Sometimes redis just fails to start - without it we can't run
# the tests - so just exit early.
cmdresult = %exec(%{clusterctrl}, '-p', %{clusterport}, 'rebuild')
if (cmdresult == '') {
	test_pass
	handled
}

#
#  Determine when initial synchronisation has been completed
#
redisserver := $ENV{REDIS_TEST_SERVER}

if (!redisserver || (redisserver == '')) {
	redisserver := "$ENV{REDIS_IPPOOL_TEST_SERVER}"
}

#  Test nodes should be running on
#  - 127.0.0.1:21001 - master [0-5460]
#  - 127.0.0.1:21004 - slave
#  - 127.0.0.1:21002 - master [5461-10922]
#  - 127.0.0.1:21005 - slave
#  - 127.0.0.1:21003 - master [10923-16383]
#  - 127.0.0.1:21006 - slave
foreach i (%range(20)) {
	#
	#  Force a remap as the slaves don't show up in the cluster immediately
	#
	timeout 1s {
		if (%redis.remap() == 'success') {
			#  Hashes to Redis cluster node master 0 (1)
			if ((%redis('SET', 'b', %{data1}) == 'OK') && \
			    (%redis('SET', 'c', %{data2}) == 'OK') && \
			    (%redis('SET', 'd', %{data3}) == 'OK')) {
				#
				#  The actual node to keyslot mapping seems to be somewhat random
				#  so we now need to figure out which slave each of those keys
				#  ended up on.
				#
				if ((%redis("-@%redis.node('b', 1)", 'GET', 'b') == data1) && \
				    (%redis("-@%redis.node('c', 1)", 'GET', 'c') == data2) && \
				    (%redis("-@%redis.node('d', 1)", 'GET', 'd') == data3)) {
					break
				}
			}
		}
	}

	request -= Module-Failure-Message[*]

	# Perform checks every half second for 10 seconds.
	#
	# The cluster tends to come up within a couple of seconds, but it takes longer
	# for the replicas to be displayed in cluster slot output (usually ~5 seconds).
	%delay(0.5)

	#
	#  If the cluster is still not behaving
	#  abandon the test to avoid false negatives
	#
	if (i == 20) {
		test_fail
		return
	}
}
