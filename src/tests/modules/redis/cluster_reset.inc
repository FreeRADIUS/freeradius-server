#
#  Include from Redis cluster tests to get clusters back into a known state
#

# Some values we need for startup
#  Determine when initial synchronisation has been completed
#
update control {
	&Tmp-Integer-0 := 0
	&Tmp-Integer-0 += 1
	&Tmp-Integer-0 += 2
	&Tmp-Integer-0 += 3
	&Tmp-Integer-0 += 4
	&Tmp-Integer-0 += 5
	&Tmp-Integer-0 += 6
	&Tmp-Integer-0 += 7
	&Tmp-Integer-0 += 8
	&Tmp-Integer-0 += 9
	&Tmp-Integer-0 += 10

	&Tmp-String-1 := "1-%{randstr:aaaaaaaa}"
	&Tmp-String-2 := "2-%{randstr:aaaaaaaa}"
	&Tmp-String-3 := "3-%{randstr:aaaaaaaa}"
}
if ("$ENV{REDIS_IPPOOL_TEST_SERVER}" != '') {
	update control {
		&Tmp-String-0 := $ENV{REDIS_IPPOOL_TEST_SERVER}
	}
} else {
	update control {
		&Tmp-String-0 := $ENV{REDIS_TEST_SERVER}
	}
}
if ("$ENV{REDIS_CLUSTER_CONTROL}" != '') {
	update control {
		&Tmp-String-8 := $ENV{REDIS_CLUSTER_CONTROL}
	}
} else {
	update control {
		&Tmp-String-8 := scripts/travis/redis-setup.sh
	}
}

if (&control:Tmp-String-0 == '') {
	test_fail
}

#  Reset the cluster
if (`%{control:Tmp-String-8}` !~ /^Run /) {
	test_fail
}

#  Test nodes should be running on
#  - 127.0.0.1:30001 - master [0-5460]
#  - 127.0.0.1:30004 - slave
#  - 127.0.0.1:30002 - master [5461-10922]
#  - 127.0.0.1:30005 - slave
#  - 127.0.0.1:30003 - master [10923-16383]
#  - 127.0.0.1:30006 - slave
foreach &control:Tmp-Integer-0 {
	#
	#  Force a remap as the slaves don't show up in the cluster immediately
	#
	if ("%{redis_remap:%{control:Tmp-String-0}:30001}" == 'success') {
		#  Hashes to Redis cluster node master 0 (1)
		if (("%{redis:SET b '%{control:Tmp-String-1}'}" == 'OK') && \
		    ("%{redis:SET c '%{control:Tmp-String-2}'}" == 'OK') && \
		    ("%{redis:SET d '%{control:Tmp-String-3}'}" == 'OK')) {
			#
			#  The actual node to keyslot mapping seems to be somewhat random
			#  so we now need to figure out which slave each of those keys
			#  ended up on.
			#
			if (("%{redis:-@%{redis_node:b 1} GET b}" == "%{control:Tmp-String-1}") && \
			    ("%{redis:-@%{redis_node:c 1} GET c}" == "%{control:Tmp-String-2}") && \
			    ("%{redis:-@%{redis_node:d 1} GET d}" == "%{control:Tmp-String-3}")) {
				break
			}
		}
	}

	update request {
		&Module-Failure-Message !* ANY
	}

	if ("%{Foreach-Variable-0}" == 10) {
		test_fail
	}

	#  FR debounces remapping if been done in the past 1s
	update {
		&Tmp-String-8 := `/bin/sleep 1.1`
	}
}
