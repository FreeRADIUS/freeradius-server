#!/bin/sh
#
#  Check Application Layer Protocol Negotiation (ALPN): the TLS extension
#  which lets both ends agree on what the tunnel carries before any of it is
#  sent.  The client offers a list of protocol names, the server picks one,
#  and the server sends back the name it picked.
#
#  The library holds no protocol names.  An application sets `alpn`,
#  `sizeof_alpn` and `alpn_required` in its fr_tls_conf_t, and unit_test_tls
#  does that from `-L names` and `-l`.  See src/lib/tls/alpn.c.
#
#  This script runs four cases, where every other script in this directory
#  runs one.  Each case needs its own pair of command lines, so one case per
#  script would mean four copies of the sixty lines of server and client
#  plumbing below for about ten lines of checks each.  The cases share one
#  configuration and one port, so they share one script instead, and
#  tls_pair() holds the plumbing once.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

RECEIPT="$OUTPUT/alpn.receipt"

mkdir -p "$OUTPUT"
rm -f "$OUTPUT"/alpn_*.log "$RECEIPT"

#
#  setsid puts the server in a new session and process group, so that
#  signalling the process group reaches the server and every process the
#  server started.  Not every system has setsid, macOS for one, so fall back
#  to running the server without setsid.
#
if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

fail() {
	echo "alpn.sh: $1"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

#
#  Run one server and one client against it, and wait for both.
#
#    tls_pair <case> <server args> -- <client args>
#
#  Sets SERVER_LOG and CLIENT_LOG for the checks which follow the call.  The
#  exit status of either program says nothing useful here, because three of
#  the four cases are meant to fail, so neither is checked.  What the two logs
#  hold is the whole of what this script tests.
#
tls_pair() {
	name=$1
	shift

	SERVER_LOG="$OUTPUT/alpn_${name}_server.log"
	CLIENT_LOG="$OUTPUT/alpn_${name}_client.log"

	server_args=""
	while [ "$1" != "--" ]; do
		server_args="$server_args $1"
		shift
	done
	shift

	$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx \
		$server_args > "$SERVER_LOG" 2>&1 &
	SERVER_PID=$!

	#
	#  Wait until the server says the listening socket is open, so the
	#  client connects when the server is ready rather than after a
	#  guessed delay.  The loop is bounded, so a server which never
	#  listens fails the test rather than hanging it.
	#
	tries=$TRIES
	while [ "$tries" -gt 0 ]; do
		grep -q "Waiting for a connection" "$SERVER_LOG" 2> /dev/null && break

		kill -0 "$SERVER_PID" 2> /dev/null || break

		tries=$((tries - 1))
		$SNOOZE
	done

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx \
		-s "127.0.0.1:$PORT" "$@" > "$CLIENT_LOG" 2>&1

	wait "$SERVER_PID" 2> /dev/null

	#
	#  An abort during the handshake looks like an ordinary failure to
	#  the checks below, because the connection dies either way.  Say so
	#  here instead, in every case, so the cause is not mistaken for the
	#  symptom.
	#
	for log in "$SERVER_LOG" "$CLIENT_LOG"; do
		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
			fail "a signal or a failed assertion appears in $log"
		fi
	done
}

######################################################################
#
#  1.  Both ends offer the same two names, in opposite orders.
#
#  The two orders are what makes this worth checking.  The server offers
#  radius/1.1 first and the client offers radius/1.0 first, so the name they
#  settle on says whose order decided it.  SSL_select_next_proto() walks the
#  server's list and takes the first name the client also offered, so the
#  answer must be radius/1.1.  If the client's order ever started deciding,
#  the answer would be radius/1.0 and this check would say so.
#
######################################################################
tls_pair both -L 'radius/1.1,radius/1.0' -- -L 'radius/1.0,radius/1.1'

grep -q 'ALPN - chose "radius/1.1"' "$SERVER_LOG" || \
	fail "the server did not choose radius/1.1, so its own order did not decide"

for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q 'ALPN - agreed on "radius/1.1"' "$log" || \
		fail "no agreement on radius/1.1 in $log"

	#
	#  The name has to arrive whole.  SSL_get0_alpn_selected() hands back
	#  the name on its own, with no leading length octet, so reading it as
	#  though it had one drops the first character and yields "adius/1.1".
	#  The exact string below is what catches that.
	#
	grep -q 'session-state.ALPN = "radius/1.1"' "$log" || \
		fail "ALPN did not reach the session-state list whole in $log"

	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "1" ] || fail "expected one completed handshake in $log, found $count"
done

######################################################################
#
#  2.  The two lists have nothing in common.
#
#  The server's select callback is what notices, and it notices during the
#  handshake, so the peer gets a fatal alert rather than a connection which
#  completes and is then torn down.  Alert 120 is no_application_protocol.
#
######################################################################
tls_pair mismatch -L 'radius/1.1' -- -L 'http/1.1'

grep -q "ALPN - no protocol in common with the peer" "$SERVER_LOG" || \
	fail "the server did not report that the two lists have nothing in common"

grep -q "Sending client fatal TLS alert (120)" "$SERVER_LOG" || \
	fail "the server did not send alert 120, no_application_protocol"

if grep -q "TLS handshake completed" "$SERVER_LOG"; then
	fail "the handshake completed, although the two ends agreed on nothing"
fi

######################################################################
#
#  3.  The server requires an agreement, and the client offers no list.
#
#  OpenSSL calls the select callback only when the client sent a list, so
#  that callback never runs here and cannot be what notices.  What notices is
#  fr_tls_session_alpn_check(), after the handshake.
#
#  This is also the case which says `alpn_required` is not merely advisory:
#  without it the same pair of command lines completes, which is what case 4
#  of alert_recv.sh would look like if ALPN were optional here.
#
######################################################################
tls_pair required -L 'radius/1.1' -l --

grep -q "ALPN - Failure, no protocols in common" "$SERVER_LOG" || \
	fail "the server did not refuse a session which agreed on no protocol"

grep -q "request.Error = ::ALPN-Failed" "$SERVER_LOG" || \
	fail "the refusal did not record ALPN-Failed"

if grep -q "TLS handshake completed" "$SERVER_LOG"; then
	fail "the handshake completed, although an agreement was required"
fi

######################################################################
#
#  4.  An agreement is required, and no names were given to agree on.
#
#  Requiring an agreement while offering nothing to agree on fails every
#  session.  fr_tls_ctx_alpn_set() says so once, at startup, rather than
#  letting every session fail for a reason the log does not explain.  No
#  client is needed, because the server never listens.
#
######################################################################
SERVER_LOG="$OUTPUT/alpn_unusable_server.log"
CLIENT_LOG="$SERVER_LOG"

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx -l \
	> "$SERVER_LOG" 2>&1

grep -q "ALPN is required, but no protocols were set" "$SERVER_LOG" || \
	fail "a required agreement with no names did not fail at startup"

if grep -q "Waiting for a connection" "$SERVER_LOG"; then
	fail "the server listened, although its ALPN configuration cannot work"
fi

touch "$RECEIPT"
exit 0
