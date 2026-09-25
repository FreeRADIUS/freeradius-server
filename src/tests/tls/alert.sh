#!/bin/sh
#
#  Run unit_test_tls with -A, so that it rejects the peer with a fatal TLS
#  alert instead of completing the handshake.  Then check that the alert
#  reached the peer.
#
#  The alert record is built by hand, in fr_tls_session_alert_send() in
#  src/lib/tls/session.c, rather than by OpenSSL.  That makes it the one place
#  which writes octets straight into a record buffer, so it is the one place
#  where a mistake sends nothing at all rather than sending something wrong.
#
#  That function resets dirty_out before writing, so the record always has
#  room, and it asserts that the write was the full seven octets.  Neither
#  guard says the octets reached the peer, which is what this test is for.
#
#  This is the only TLS test where the handshake itself fails.  The reject
#  test fails a session, but only after the handshake has succeeded.
#
#  The check is what the client saw, not what the server logged.  Only the
#  client can tell us the octets left the machine.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

LOG="$OUTPUT/alert.log"
RECEIPT="$OUTPUT/alert.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

fail() {
	echo "alert.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "alert.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -A > "$LOG" 2>&1 &
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

echo "--- openssl s_client ---" >> "$LOG"

#
#  s_client exits non-zero because the handshake failed, which is the point,
#  so its exit status says nothing and is ignored.
#
echo | openssl s_client -connect "127.0.0.1:$PORT" \
	-cert "$CERTDIR/client.pem" \
	-key "$CERTDIR/client.key" -pass pass:whatever \
	-CAfile "$CERTDIR/ca.pem" >> "$LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

#
#  SSL_AD_ACCESS_DENIED is alert number 49.  OpenSSL prints both the name and
#  the number, and both are checked: the name alone would also match a log
#  line about some other alert, and the number alone is easy to misread.
#
grep -q "alert access denied" "$LOG" || \
	fail "the client did not report the alert, so fr_tls_session_alert_send() sent nothing"

grep -q "SSL alert number 49" "$LOG" || \
	fail "the client reported an alert, but not SSL_AD_ACCESS_DENIED (49)"

#
#  The handshake must not have completed.  If it did, the alert was sent but
#  ignored, which is a different bug wearing the same clothes.
#
if grep -q "TLS handshake completed" "$LOG"; then
	fail "the handshake completed, so the alert did not stop it"
fi

touch "$RECEIPT"
exit 0
