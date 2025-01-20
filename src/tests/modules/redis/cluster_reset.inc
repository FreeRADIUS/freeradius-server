#
#  Include from Redis cluster tests to get clusters back into a known state
#
string clusterctrl
string redisserver
string data1
string data2
string data3
string cmdresult

# Some values we need for startup
control.Filter-Id := { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 }

data1 := "1-%randstr('aaaaaaaa')"
data2 := "2-%randstr('aaaaaaaa')"
data3 := "3-%randstr('aaaaaaaa')"

if ("$ENV{REDIS_CLUSTER_CONTROL}" == '') {
	clusterctrl := 'scripts/ci/redis-setup.sh'
} else {
	clusterctrl := $ENV{REDIS_CLUSTER_CONTROL}
}

#
#  Reset the cluster
#
%exec(%{clusterctrl}, stop)
%exec(%{clusterctrl}, clean)
%exec(%{clusterctrl}, start)

# Sometimes redis just fails to start - without it we can't run
# the tests - so just exit early.
cmdresult = %exec(%{clusterctrl}, create)
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
#  - 127.0.0.1:30001 - master [0-5460]
#  - 127.0.0.1:30004 - slave
#  - 127.0.0.1:30002 - master [5461-10922]
#  - 127.0.0.1:30005 - slave
#  - 127.0.0.1:30003 - master [10923-16383]
#  - 127.0.0.1:30006 - slave
foreach control.Filter-Id {
	#
	#  Force a remap as the slaves don't show up in the cluster immediately
	#
	if (%redis.remap(%{redisserver}:30001) == 'success') {
		#  Hashes to Redis cluster node master 0 (1)
		if ((%redis(SET, b, %{data1}) == 'OK') && \
		    (%redis(SET, c, %{data2}) == 'OK') && \
		    (%redis(SET, d, %{data3}) == 'OK')) {
			#
			#  The actual node to keyslot mapping seems to be somewhat random
			#  so we now need to figure out which slave each of those keys
			#  ended up on.
			#
			if ((%redis("-@%redis.node(b, 1)", GET, b) == %{data1}) && \
			    (%redis("-@%redis.node(c, 1)", GET, c) == %{data2}) && \
			    (%redis("-@%redis.node(d, 1)", GET, d) == %{data3})) {
				break
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
	if (%{Foreach-Variable-0} == 20) {
		test_fail
		return
	}
}
