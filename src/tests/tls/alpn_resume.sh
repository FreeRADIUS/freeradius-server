#!/bin/sh
#
#  Check that a session which negotiated radius/1.1 carries the negotiated
#  name into the resumed session.
#
#  RFC 9765 Section 3.5 says a session which negotiated radius/1.1 can only be
#  resumed with radius/1.1.  The server enforces the rule with the name that
#  fr_tls_session_alpn_check() puts in `session-state.TLS-ALPN`, which the TLS
#  library writes into the ticket.  The client enforces the rule with the name
#  that OpenSSL records on the session.  See src/lib/tls/alpn.c.
#
#  Each case runs two connections.  The first connection negotiates
#  radius/1.1 with both ends offering radius/1.1 and radius/1.0, and the second
#  connection resumes the session.  The checks on the server answer two
#  questions which the design of the sticky entry depends on:
#
#    1.  Does the server restore `session-state` before
#        fr_tls_session_alpn_check() runs on the resumed connection?  The
#        server logs the name that `session-state` holds when the check
#        starts.
#    2.  Does a TLS 1.3 ticket which is issued after the handshake carry
#        `session-state.TLS-ALPN`?  The delayed case issues the ticket after the
#        handshake, and the second connection finds the name in the ticket.
#
#  The cases are stateful tickets, where the server keeps the session, stateless
#  tickets, where the peer holds the session, and stateless tickets which the
#  server delays until after the handshake.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding alpn_stateful.conf and alpn_stateless.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

RECEIPT="$OUTPUT/alpn_resume.receipt"

mkdir -p "$OUTPUT"
rm -f "$OUTPUT"/alpn_resume_*.log "$RECEIPT"

fail() {
	fail_message="$1"

	echo "alpn_resume.sh: $fail_message"
	for fail_log in "$OUTPUT"/alpn_resume_*.log; do
		[ -e "$fail_log" ] || continue
		echo "--- $fail_log ---"
		cat "$fail_log"
	done
	exit 1
}

#
#  run <case> <config name> [server options]
#
#  The server options are the ones for the server only, such as -T for
#  delayed tickets.
#
run() {
	run_name="$1"
	run_conf="$2"
	run_server_options="$3"

	run_server_log="$OUTPUT/alpn_resume_${run_name}_server.log"
	run_client_log="$OUTPUT/alpn_resume_${run_name}_client.log"

	CLIENT_LOG="$run_client_log"
	CLIENT_CONF="$run_conf"
	export CLIENT_LOG CLIENT_CONF

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$run_conf" -xx -c 2 -P \
		-L 'radius/1.1,radius/1.0' $run_server_options \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$CLIENT_CONF" -xx -c 2 \
			-L "radius/1.1,radius/1.0" \
			-s "127.0.0.1:$PORT" > "$CLIENT_LOG" 2>&1' \
		> "$run_server_log" 2>&1

	for run_log in "$run_server_log" "$run_client_log"; do
		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$run_log"; then
			fail "$run_name: a signal or a failed assertion appears in $run_log"
		fi

		#
		#  Both ends have to complete both connections, and the second one
		#  has to resume.
		#
		run_count=$(grep -c "TLS handshake completed" "$run_log")
		[ "$run_count" = "2" ] || \
			fail "$run_name: expected two completed handshakes in $run_log, found $run_count"

		run_count=$(grep -c "resumed    : yes" "$run_log")
		[ "$run_count" = "1" ] || \
			fail "$run_name: expected one resumed session in $run_log, found $run_count"

		#
		#  Each connection negotiates radius/1.1.
		#
		run_count=$(grep -c 'ALPN - agreed on "radius/1.1"' "$run_log")
		[ "$run_count" = "2" ] || \
			fail "$run_name: expected two agreements on radius/1.1 in $run_log, found $run_count"
	done

	#
	#  Question 1.  The first connection is new, so session-state holds no
	#  name when the server chooses a protocol.  The second connection is
	#  resumed, and session-state already holds the name from the ticket when
	#  the server chooses a protocol.  The log line appears once, on the
	#  second connection, before the line which says what the server chose.
	#
	run_count=$(grep -c 'ALPN - session-state.TLS-ALPN = "radius/1.1" from the resumed session' "$run_server_log")
	[ "$run_count" = "1" ] || \
		fail "$run_name: expected the server to restore session-state before choosing once, found $run_count"

	run_restored_line=$(grep -n 'Restoring session-state' "$run_server_log" | cut -d: -f1)
	run_chose_line=$(grep -n 'ALPN - chose "radius/1.1"' "$run_server_log" | tail -1 | cut -d: -f1)
	[ "$run_restored_line" -lt "$run_chose_line" ] || \
		fail "$run_name: the server restored session-state at line $run_restored_line, after it chose at line $run_chose_line"

	#
	#  The server holds one name after the check, not the restored name and
	#  a second copy of the name.
	#
	run_count=$(grep 'session-state.TLS-ALPN = "radius/1.1"' "$run_server_log" | grep -vc 'from the resumed session')
	[ "$run_count" = "2" ] || \
		fail "$run_name: expected one session-state.TLS-ALPN for each connection, found $run_count"

	#
	#  Question 2.  With delayed tickets, the server issues the ticket after the
	#  handshake, so the first ticket is written after the first completed
	#  handshake.  The second connection finds the name in the ticket, which
	#  the check on the resumed connection above has shown.
	#
	if [ "$run_server_options" = "-T" ]; then
		run_done_line=$(grep -n "TLS handshake completed" "$run_server_log" | head -1 | cut -d: -f1)
		run_added_line=$(grep -n "Adding session-state" "$run_server_log" | head -1 | cut -d: -f1)
		[ "$run_added_line" -gt "$run_done_line" ] || \
			fail "$run_name: the ticket was issued at line $run_added_line, before the handshake finished at line $run_done_line"
	fi

	#
	#  The client offers only radius/1.1 when the client resumes the session.
	#  The client has to read the name from the session which OpenSSL
	#  recorded.
	#
	grep -q 'resuming a session which negotiated "radius/1.1", offering only that name' "$run_client_log" || \
		fail "$run_name: the client did not restrict its list to radius/1.1 when resuming"
}

run stateless alpn_stateless ''
run dtls dtls ''
run delayed alpn_stateless '-T'
run stateful alpn_stateful ''

touch "$RECEIPT"
exit 0
