#!/bin/sh
#
#  Run two connections with stateless session resumption, and check that the
#  second one resumed from a session ticket rather than from the server's
#  cache.
#
#  Stateless resumption puts the session in a ticket the peer holds, so the
#  server keeps nothing.  `load session` and `store session` are therefore
#  never called on the server.  What runs in their place is `encode session`
#  before the session-state list is written into a ticket, and
#  `decode session` once a presented ticket has put that list back.  Nothing
#  else in this directory reaches either section.
#
#  The client is the other way round.  The ticket is handed to the client, and
#  the client has to keep it somewhere to offer it back, so the client does use
#  `load session` and `store session`.  The assertions below are split for that
#  reason: what is forbidden on the server is required on the client.
#
#  Two connections are the smallest number that can show resumption.  The first
#  issues a ticket, the second presents it.
#
#  The server also sends one byte of application data, 0x00, once each
#  handshake is done, which is what -P does.  Tickets precede application data,
#  so the byte is a positive signal to the client that no ticket is still
#  coming.  Without it a client which is never going to get a ticket has
#  nothing to wait on but a timer.
#
#  This is also the only test which negotiates TLS 1.3.  Every other
#  configuration here pins tls_max_version to 1.2, because stateful resumption
#  is not defined above that.
#
#  Each program writes a receipt file only when that program exits
#  successfully, so a receipt records that both connections worked.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding stateless.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/stateless.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/stateless_server.log"
CLIENT_LOG="$OUTPUT/stateless_client.log"
SERVER_RECEIPT="$OUTPUT/stateless_server.receipt"
CLIENT_RECEIPT="$OUTPUT/stateless_client.receipt"
RECEIPT="$OUTPUT/stateless.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

#
#  setsid puts the server in a new session and process group, so that
#  signalling the process group reaches the server and every process the
#  server started.  "session" here is the process kind, not the TLS kind.
#  Not every system has setsid, macOS for one, so fall back to running the
#  server without setsid.  The trap below kills the server either way.
#
if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n stateless -xx -c 2 -P \
	-r "$SERVER_RECEIPT" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

#
#  Wait until the server logs "Waiting for a connection".  The log line says
#  the listening socket is open, so the client connects as soon as the server
#  is ready rather than after a guessed delay.  The loop bounds the wait, so a
#  server that never opens the socket fails the test rather than hanging it.
#
if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$SERVER_LOG" 2> /dev/null && break

	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n stateless -xx -c 2 \
	-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

fail() {
	echo "$1"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

[ -e "$SERVER_RECEIPT" ] || fail "server did not create $SERVER_RECEIPT"
[ -e "$CLIENT_RECEIPT" ] || fail "client did not create $CLIENT_RECEIPT"

#
#  Both ends have to complete both connections, and the second one has to
#  resume.  Both ends must agree that it resumed.
#
for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "2" ] || fail "expected two completed handshakes in $log, found $count"

	count=$(grep -c "resumed    : yes" "$log")
	[ "$count" = "1" ] || fail "expected one resumed session in $log, found $count"

	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
		fail "a signal or a failed assertion appears in $log"
	fi
done

#
#  Resumption must have been stateless, which is what TLS 1.3 gives us here.
#  A run which fell back to 1.2 would resume statefully and prove nothing.
#
grep -q "version    : TLSv1.3" "$SERVER_LOG" || \
	fail "the server did not negotiate TLS 1.3, so resumption was not stateless"

#
#  The server keeps nothing, so neither cache section may run there.  This is
#  the behaviour the whole configuration exists to pin.
#
for section in "load session" "store session"; do
	if grep -q "# $section" "$SERVER_LOG"; then
		fail "'$section' ran on the server, with stateless resumption"
	fi
done

#
#  `encode session` runs once per ticket issued, which is once per connection.
#
count=$(grep -c "# encode session" "$SERVER_LOG")
[ "$count" = "2" ] || fail "expected two encode session on the server, found $count"

#
#  `decode session` runs once, on the connection which presented a ticket.
#
count=$(grep -c "# decode session" "$SERVER_LOG")
[ "$count" = "1" ] || fail "expected one decode session on the server, found $count"

#
#  -P makes the server send one byte of application data once the handshake is
#  done.  A server sends every session ticket before its first byte of
#  application data, so a client which has seen application data knows that no
#  ticket is still on its way.  That is what lets a client stop waiting without
#  guessing, and it is what fr_tls_session_is_init_finished() reads.
#
count=$(grep -c "Sent one byte of application data" "$SERVER_LOG")
[ "$count" = "2" ] || fail "expected the server to send application data twice, found $count"

#
#  The client is where the ticket is kept, so the client does use the cache.
#  Without this the second connection would have nothing to present, and the
#  resumption checked above would be the server resuming from its own store.
#
count=$(grep -c "# store session" "$CLIENT_LOG")
[ "$count" = "2" ] || fail "expected two store session on the client, found $count"

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
