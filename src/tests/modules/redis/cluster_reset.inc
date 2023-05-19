#
#  Include from Redis cluster tests to get clusters back into a known state
#

# Some values we need for startup
&control += {
	&Tmp-Integer-0 = 0
	&Tmp-Integer-0 = 1
	&Tmp-Integer-0 = 2
	&Tmp-Integer-0 = 3
	&Tmp-Integer-0 = 4
	&Tmp-Integer-0 = 5
	&Tmp-Integer-0 = 6
	&Tmp-Integer-0 = 7
	&Tmp-Integer-0 = 8
	&Tmp-Integer-0 = 9
	&Tmp-Integer-0 = 10
	&Tmp-Integer-0 = 11
	&Tmp-Integer-0 = 12
	&Tmp-Integer-0 = 13
	&Tmp-Integer-0 = 14
	&Tmp-Integer-0 = 15
	&Tmp-Integer-0 = 16
	&Tmp-Integer-0 = 17
	&Tmp-Integer-0 = 18
	&Tmp-Integer-0 = 19
	&Tmp-Integer-0 = 20
	&Tmp-Integer-0 = 21
}

&control.Tmp-String-0 := "1-%{randstr:aaaaaaaa}"
&control.Tmp-String-1 := "2-%{randstr:aaaaaaaa}"
&control.Tmp-String-2 := "3-%{randstr:aaaaaaaa}"

if ("$ENV{REDIS_CLUSTER_CONTROL}" == '') {
	&control.Tmp-String-8 := 'scripts/ci/redis-setup.sh'
} else {
	&control.Tmp-String-8 := "$ENV{REDIS_CLUSTER_CONTROL}"
}

#
#  Reset the cluster
#
&Tmp-String-0 := `%{control.Tmp-String-8} stop`
&Tmp-String-0 := `%{control.Tmp-String-8} clean`
&Tmp-String-0 := `%{control.Tmp-String-8} start`
&Tmp-String-0 := `%{control.Tmp-String-8} create`

#
#  Determine when initial synchronisation has been completed
#
&Tmp-String-0 := $ENV{REDIS_TEST_SERVER}

if (!&Tmp-String-0 || (&Tmp-String-0 == '')) {
	&Tmp-String-0 := "$ENV{REDIS_IPPOOL_TEST_SERVER}"
}

#  Test nodes should be running on
#  - 127.0.0.1:30001 - master [0-5460]
#  - 127.0.0.1:30004 - slave
#  - 127.0.0.1:30002 - master [5461-10922]
#  - 127.0.0.1:30005 - slave
#  - 127.0.0.1:30003 - master [10923-16383]
#  - 127.0.0.1:30006 - slave
foreach &control.Tmp-Integer-0 {
	#
	#  Force a remap as the slaves don't show up in the cluster immediately
	#
	if ("%(redis.remap:%{Tmp-String-0}:30001)" == 'success') {
		#  Hashes to Redis cluster node master 0 (1)
		if (("%(redis:SET b "%{control.Tmp-String-0}")" == 'OK') && \
		    ("%(redis:SET c "%{control.Tmp-String-1}")" == 'OK') && \
		    ("%(redis:SET d "%{control.Tmp-String-2}")" == 'OK')) {
			#
			#  The actual node to keyslot mapping seems to be somewhat random
			#  so we now need to figure out which slave each of those keys
			#  ended up on.
			#
			if (("%(redis:-@%(redis.node:b 1) GET b)" == "%{control.Tmp-String-0}") && \
			    ("%(redis:-@%(redis.node:c 1) GET c)" == "%{control.Tmp-String-1}") && \
			    ("%(redis:-@%(redis.node:d 1) GET d)" == "%{control.Tmp-String-2}")) {
				break
			}
		}
	}

	&request -= &Module-Failure-Message[*]

	# Perform checks every half second for 10 seconds.
	#
	# The cluster tends to come up within a couple of seconds, but it takes longer
	# for the replicas to be displayed in cluster slot output (usually ~5 seconds).
	%(delay:0.5)

	#
	#  If the cluster is still not behaving
	#  abandon the test to avoid false negatives
	#
	if ("%{Foreach-Variable-0}" == 20) {
		test_fail
		return
	}
}
