#!/bin/sh
#
#  Make unit_test_tls send a fatal TLS alert, and check that the alert
#  reached the reply list as `Alert`.
#
#  alert_recv.sh covers the opposite direction.  There the peer sends the
#  alert and the alert lands in the request list.  Here unit_test_tls sends
#  the alert and the alert lands in the reply list.  The list which holds the
#  alert is what says which end sent the alert, so the two tests are a pair:
#  each one checks that its own list holds the alert, and that the other list
#  does not.
#
#  alert.sh also sends an alert, by a different route.  Under -A,
#  unit_test_tls builds the seven octets of the alert record by hand, in
#  fr_tls_session_alert_send().  Here OpenSSL builds and sends the alert, and
#  fr_tls_session_info_cb() is what sees the alert.  Those are two separate
#  call sites in src/lib/tls/session.c, and each call site records the alert
#  for itself.
#
#  The alert is provoked by connecting without a client certificate.  The
#  test configuration sets `require_client_certificate = yes`, so OpenSSL
#  refuses the connection and sends `handshake_failure`, which the dictionary
#  names `Handshake-Failure`, alert 40.  That is the commonest way a real
#  EAP-TLS handshake fails, which is why this test uses it rather than
#  something more contrived.
#
#  `Error` in the session-state list carries `Sent-Alert`, which is what
#  tells an administrator to look in the reply list rather than the request
#  list.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the certificate authority certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

LOG="$OUTPUT/alert_send.log"
CLIENT_LOG="$OUTPUT/alert_send_client.log"
RECEIPT="$OUTPUT/alert_send.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "alert_send.sh: $1"
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

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx > "$LOG" 2>&1 &
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

while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$LOG" 2> /dev/null && break

	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

#
#  s_client writes to its own file.  unit_test_tls is still writing to $LOG
#  at this point, and two programs appending to one file interleave their
#  output, which loses whichever lines land in the gap.
#
#  No -cert and no -key, which is the whole point: the server asks for a
#  certificate, s_client has none to give, and the server sends the alert.
#  s_client exits non-zero because the handshake failed, so the script
#  ignores the exit status of s_client.
#
echo | openssl s_client -connect "127.0.0.1:$PORT" \
	-CAfile "$CERTDIR/ca.pem" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

#
#  The server has to have sent the alert.  Without this check the checks
#  below would pass on a run where s_client never connected.
#
grep -q "Sending client fatal TLS alert (40)" "$LOG" || \
	fail "unit_test_tls did not send a fatal handshake_failure alert"

#
#  The alert must be in the reply list, with both members.  The names come
#  from share/dictionary/tls/dictionary.freeradius.
#
grep -q "reply.Alert = { Level = ::Fatal, Description = ::Handshake-Failure }" "$LOG" || \
	fail "the alert was logged but not added to the reply list as Alert"

count=$(grep -c "reply.Alert = {" "$LOG")
[ "$count" = "1" ] || fail "expected one Alert in the reply list, found $count"

#
#  A sent alert must not appear in the request list, which is where a
#  received alert goes.
#
if grep -q "Adding Alert = {" "$LOG"; then
	fail "a sent alert was also put in the request list"
fi

#
#  `Error` says what went wrong.  `Sent-Alert` is the value which tells an
#  administrator to look in the reply list.
#
grep -q "session-state.Error = ::Sent-Alert" "$LOG" || \
	fail "the Sent-Alert error was not added to the session-state list"

#
#  What `fail session { ... }` can read is checked in reject.sh rather than
#  here.  Both scripts reach the section now that fr_tls_connection_failed()
#  defers a failure while a record is still waiting for OpenSSL, but reject.sh
#  runs unit_test_tls at both ends, so it keeps the check away from whatever
#  openssl s_client does when it closes.
#
touch "$RECEIPT"
exit 0
