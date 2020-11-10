#
#  Include from Redis cluster tests to get clusters back into a known state
#

# Some values we need for startup
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
	&Tmp-String-0 := "1-%{randstr:aaaaaaaa}"
	&Tmp-String-1 := "2-%{randstr:aaaaaaaa}"
	&Tmp-String-2 := "3-%{randstr:aaaaaaaa}"
}

if ("$ENV{REDIS_CLUSTER_CONTROL}" == '') {
	update control {
		&Tmp-String-8 := 'scripts/ci/redis-setup.sh'
	}
} else {
	update control {
		&Tmp-String-8 := "$ENV{REDIS_CLUSTER_CONTROL}"
	}
}

#
#  Reset the cluster
#
update control {
	&Tmp-String-0 = `%{control.Tmp-String-8} stop`
	&Tmp-String-0 = `%{control.Tmp-String-8} clean`
	&Tmp-String-0 = `%{control.Tmp-String-8} start`
	&Tmp-String-0 = `%{control.Tmp-String-8} create`
}

#
#  Determine when initial synchronisation has been completed
#
update request {
	&Tmp-String-0 := $ENV{REDIS_TEST_SERVER}
}
if (!&Tmp-String-0 || (&Tmp-String-0 == '')) {
	update request {
		&Tmp-String-0 := $ENV{REDIS_IPPOOL_TEST_SERVER}
	}
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
	if ("%{redis_remap:%{Tmp-String-0}:30001}" == 'success') {
		#  Hashes to Redis cluster node master 0 (1)
		if (("%{redis:SET b '%{control.Tmp-String-0}'}" == 'OK') && \
		    ("%{redis:SET c '%{control.Tmp-String-1}'}" == 'OK') && \
		    ("%{redis:SET d '%{control.Tmp-String-2}'}" == 'OK')) {
			#
			#  The actual node to keyslot mapping seems to be somewhat random
			#  so we now need to figure out which slave each of those keys
			#  ended up on.
			#
			if (("%{redis:-@%{redis_node:b 1} GET b}" == "%{control.Tmp-String-0}") && \
			    ("%{redis:-@%{redis_node:c 1} GET c}" == "%{control.Tmp-String-1}") && \
			    ("%{redis:-@%{redis_node:d 1} GET d}" == "%{control.Tmp-String-2}")) {
				break
			}
		}
	}

	update request {
		&Module-Failure-Message !* ANY
	}

	# Perform checks every 0.5 seconds
	update {
		&Tmp-Integer-0 := `/bin/sleep 0.5`
	}

	if ("%{Foreach-Variable-0}" == 10) {
		test_fail
	}
}
