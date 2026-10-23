#!/bin/sh
#
#  Run two connections with stateful session resumption over TLS 1.3, and
#  check that the second one resumed from the session in the server's cache.
#
#  A TLS 1.3 server which is told not to issue stateless tickets issues a
#  stateful ticket instead.  The ticket holds only a session ID, so the server
#  keeps the session itself.  `store session` therefore runs on the server
#  when the ticket is issued, and `load session` runs when the client presents
#  the ID.  `encode session` and `decode session` belong to stateless tickets,
#  so neither section may run on the server.
#
#  Both ends set tls_min_version to 1.3, see stateful_tls13.conf.  A handshake
#  which fell back to TLS 1.2 would fail instead of resuming, so the test
#  cannot pass by resuming a TLS 1.2 session.
#
#  Three cases, one server run each:
#
#    default  The ticket is issued in the handshake, and `store session` runs
#             there.
#    delayed  -T sets `delayed_tickets` on the server, which EAP does on every
#             TLS configuration.  EAP issues the ticket once the inner
#             authentication has succeeded.  `store session` has to wait for
#             that, so the first one has to be logged after the handshake has
#             finished.
#    hrr      The server only accepts the P-256 curve, see
#             stateful_tls13_hrr.conf.  The server sends a HelloRetryRequest,
#             and OpenSSL asks `load session` for the session a second time,
#             for one connection.  The second answer has to be the same
#             session, and `load session` must still run only once.
#
#  The server sends one byte of application data, 0x00, once each handshake is
#  done, which is what -P does.  Tickets precede application data, so the byte
#  tells the client that no ticket is still coming.
#
#  Each program writes a receipt file only when that program exits
#  successfully, so a receipt records that both connections worked.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding stateful_tls13.conf and stateful_tls13_hrr.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/stateful_tls13.conf.
#
#  $Id$
#

RECEIPT="$OUTPUT/stateful_tls13.receipt"

mkdir -p "$OUTPUT"
rm -f "$RECEIPT"

fail() {
	echo "$1"
	for f in "$OUTPUT"/stateful_tls13_*.log; do
		[ -e "$f" ] || continue
		echo "--- $f ---"
		cat "$f"
	done
	exit 1
}

#
#  run <case> <config name> <delayed> <hello retry request> [server options]
#
run() {
	name="$1"
	conf="$2"
	delayed="$3"
	hrr="$4"
	shift 4

	server_log="$OUTPUT/stateful_tls13_${name}_server.log"
	client_log="$OUTPUT/stateful_tls13_${name}_client.log"
	server_receipt="$OUTPUT/stateful_tls13_${name}_server.receipt"
	client_receipt="$OUTPUT/stateful_tls13_${name}_client.receipt"

	rm -f "$server_log" "$client_log" "$server_receipt" "$client_receipt"

	export client_log client_receipt conf

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 -P "$@" \
		-r "$server_receipt" \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 \
			-s "127.0.0.1:$PORT" -r "$client_receipt" > "$client_log" 2>&1' \
		> "$server_log" 2>&1

	[ -e "$server_receipt" ] || fail "$name: server did not create $server_receipt"
	[ -e "$client_receipt" ] || fail "$name: client did not create $client_receipt"

	#
	#  Both ends have to complete both connections, and the second one has to
	#  resume.  Both ends must agree that it resumed.
	#
	for log in "$server_log" "$client_log"; do
		count=$(grep -c "TLS handshake completed" "$log")
		[ "$count" = "2" ] || fail "$name: expected two completed handshakes in $log, found $count"

		count=$(grep -c "resumed    : yes" "$log")
		[ "$count" = "1" ] || fail "$name: expected one resumed session in $log, found $count"

		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
			fail "$name: a signal or a failed assertion appears in $log"
		fi
	done

	#
	#  Every connection must be TLS 1.3.
	#
	count=$(grep -c "version    : TLSv1.3" "$server_log")
	[ "$count" = "2" ] || fail "$name: expected two TLS 1.3 connections on the server, found $count"

	#
	#  The server keeps the session, so the server runs `store session` for the
	#  ticket of each connection.  The resumed connection gets a fresh ticket,
	#  which is the second `store session`.  `load session` runs once, on the
	#  connection which presented a session ID.
	#
	count=$(grep -c "# store session" "$server_log")
	[ "$count" = "2" ] || fail "$name: expected two store session on the server, found $count"

	count=$(grep -c "# load session" "$server_log")
	[ "$count" = "1" ] || fail "$name: expected one load session on the server, found $count"

	#
	#  The client stores the ticket of each connection, because the client keeps
	#  the session ID it presents.  Without the first store, the second
	#  connection would have nothing to present.
	#
	count=$(grep -c "# store session" "$client_log")
	[ "$count" = "2" ] || fail "$name: expected two store session on the client, found $count"

	#
	#  The sections for stateless tickets must not run.
	#
	for section in "encode session" "decode session"; do
		if grep -q "# $section" "$server_log"; then
			fail "$name: '$section' ran on the server, with stateful resumption"
		fi
	done

	#
	#  A HelloRetryRequest is a ServerHello which asks the client for another
	#  key share.  The server logs it as a second server_hello message in the
	#  connection.  Two connections send two server_hello messages when no
	#  retry happens, and four when every connection has one.  The cases
	#  without a retry must not have one, or the HelloRetryRequest case tests
	#  nothing which the other cases do not.
	#
	count=$(grep -c "send TLS 1.3, handshake\[length [0-9]*\], server_hello" "$server_log")
	if [ "$hrr" = "1" ]; then
		[ "$count" = "4" ] || fail "$name: expected four server_hello messages with HelloRetryRequests, found $count"
	else
		[ "$count" = "2" ] || fail "$name: expected two server_hello messages without HelloRetryRequests, found $count"
	fi

	#
	#  With delayed tickets, the first `store session` has to be logged after
	#  the first "TLS handshake completed".
	#
	if [ "$delayed" = "1" ]; then
		done_line=$(grep -n "TLS handshake completed" "$server_log" | head -1 | cut -d: -f1)
		store_line=$(grep -n "# store session" "$server_log" | head -1 | cut -d: -f1)
		[ "$store_line" -gt "$done_line" ] || \
			fail "$name: store session ran at line $store_line, before the handshake finished at line $done_line"
	fi
}

run default stateful_tls13 0 0
run delayed stateful_tls13 1 0 -T
run hrr stateful_tls13_hrr 0 1

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
