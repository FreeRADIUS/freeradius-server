#!/bin/sh
#
#  Run one connection where the server issues no session ticket, and check
#  that the client finishes anyway because application data arrived.
#
#  A TLS 1.3 client which expects a ticket cannot tell "the ticket is still on
#  its way" from "there was never going to be one".  What settles it is the
#  first byte of application data: a server sends every ticket it is going to
#  send before that byte, so once the byte arrives no ticket is coming.
#  fr_tls_session_is_init_finished() reads exactly that.
#
#  stateless.sh cannot pin this.  There the server does issue a ticket, it
#  arrives first, and the client finishes on the ticket without ever reading
#  the application data.  Here the server is `mode = disabled`, so no ticket
#  exists and the byte is the only thing which can release the client.
#
#  The failure mode if the signal is lost is not a wrong answer but a stall.
#  The client reads the byte, has nothing to end its wait, and never finishes;
#  the server meanwhile has finished and closed, so the client dies on the
#  closed connection rather than completing.  Measured, not assumed: removing
#  the signal fails this test with "Error on connection" and no completed
#  handshake, while the other seven still pass.
#
#  The post-handshake timer in src/bin/unit_test_tls.c does not fire here,
#  because the close arrives first.  The timer is the backstop for a peer
#  which sends neither a ticket nor application data and stays connected.
#
#  One connection is enough.  There is nothing to resume, and a second
#  connection would only repeat the first.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding no_ticket.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/no_ticket.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/no_ticket_server.log"
CLIENT_LOG="$OUTPUT/no_ticket_client.log"
SERVER_RECEIPT="$OUTPUT/no_ticket_server.receipt"
CLIENT_RECEIPT="$OUTPUT/no_ticket_client.receipt"
RECEIPT="$OUTPUT/no_ticket.receipt"

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

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_ticket -xx -P \
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

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_ticket -xx \
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

for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "1" ] || fail "expected one completed handshake in $log, found $count"

	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
		fail "a signal or a failed assertion appears in $log"
	fi
done

#
#  The version matters.  Session tickets are a TLS 1.3 feature, so a run which
#  negotiated 1.2 would have nothing to wait for and would pass whatever the
#  library did.
#
grep -q "version    : TLSv1.3" "$CLIENT_LOG" || \
	fail "the client did not negotiate TLS 1.3, so it was never waiting for a ticket"

#
#  The server must have sent the byte, or there was no signal to test.
#
grep -q "Sent one byte of application data" "$SERVER_LOG" || \
	fail "the server did not send application data, so nothing could release the client"

#
#  And no ticket may have arrived.  A ticket reaches the client through the
#  new-session callback, which queues the store, so `store session` running on
#  the client means a ticket turned up and settled the wait instead.
#
if grep -q "# store session" "$CLIENT_LOG"; then
	fail "the client stored a session, so a ticket arrived and the byte proved nothing"
fi

#
#  The client must have been released by the byte rather than by the backstop.
#  The timer firing would mean the byte did not do its job.
#
if grep -q "Timed out waiting for data after the handshake" "$CLIENT_LOG"; then
	fail "the client timed out, so the application data did not release it"
fi

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
