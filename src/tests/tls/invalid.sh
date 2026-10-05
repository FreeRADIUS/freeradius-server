#!/bin/sh
#
#  Check what FreeRADIUS sends to the peer when FreeRADIUS, rather than
#  OpenSSL, refuses a handshake.
#
#  FreeRADIUS enforces several rules on every record which FreeRADIUS reads.
#  src/lib/tls/alerts.md lists the rules.  When a record breaks a rule,
#  FreeRADIUS marks the session invalid, and the next round does not continue
#  the handshake.  RFC 9846 Section 6.2 says that an implementation which
#  encounters a fatal error "SHOULD send an appropriate fatal alert and MUST
#  close the connection".  The refusal must therefore reach the peer as an
#  alert, and not as a closed socket alone.
#
#  Internal-Error is the description which FreeRADIUS sends when no more
#  specific description fits the rule which the record broke.
#
#  The server runs with -I.  The -I option marks the session invalid part way
#  through the handshake, in the same way that fr_tls_session_msg_cb() marks
#  the session invalid when the server refuses a record.  Sending a malformed
#  record instead would need a TLS implementation inside this script.
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

LOG="$OUTPUT/invalid_server.log"
CLIENT_LOG="$OUTPUT/invalid_client.log"
RECEIPT="$OUTPUT/invalid.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "invalid.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx -I \
	> "$LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

#
#  Wait until the server logs that the listening socket is open.  The client
#  then connects when the server is ready, rather than after a guessed delay.
#  The loop is bounded, so a server which never listens fails the test rather
#  than hanging the test.
#
while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$LOG" 2> /dev/null && break

	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

#
#  This test requires a failed handshake, so the client exits non-zero.  The
#  exit status therefore does not distinguish a pass from a failure, and this
#  script does not check the exit status.
#
$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx \
	-s "127.0.0.1:$PORT" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

for log in "$LOG" "$CLIENT_LOG"; do
	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
		fail "a signal or a failed assertion appears in $log"
	fi
done

######################################################################
#
#  What the server did.
#
######################################################################
grep -q "Preventing invalid session from continuing" "$LOG" || \
	fail "the server did not refuse to continue an invalid session"

grep -q "request.Error = ::Session-Invalid" "$LOG" || \
	fail "the refusal did not record Session-Invalid"

grep -q "reply.Alert = { Level = ::Fatal, Description = ::Internal-Error }" "$LOG" || \
	fail "the server did not queue a fatal Internal-Error alert"

grep -q "request.Error = ::Sent-Alert" "$LOG" || \
	fail "the server recorded no Sent-Alert, so the alert was never written out"

######################################################################
#
#  What the client read.
#
#  The client checks are the half which matters.  A server can queue an alert
#  and still close the socket before writing the alert.  The server's own log
#  does not distinguish the two cases, and only the client log shows which
#  case happened.
#
#  SSL_AD_INTERNAL_ERROR is alert number 80.
#
######################################################################
grep -q "fatal, internal_error" "$CLIENT_LOG" || \
	fail "the client did not read a fatal internal_error alert, so none reached it"

grep -q "SSL alert number 80" "$CLIENT_LOG" || \
	fail "the client read an alert, but not SSL_AD_INTERNAL_ERROR (80)"

grep -q "request.Error = ::Received-Alert" "$CLIENT_LOG" || \
	fail "the client did not record Received-Alert"

#
#  Neither end may record a completed handshake.  When an end records a
#  completed handshake, the peer received the alert and ignored the alert.  A
#  peer which ignores an alert is a different bug, and the two bugs produce
#  the same log lines.
#
for log in "$LOG" "$CLIENT_LOG"; do
	if grep -q "TLS handshake completed" "$log"; then
		fail "the handshake completed in $log, so the refusal did not stop it"
	fi
done

touch "$RECEIPT"
exit 0
