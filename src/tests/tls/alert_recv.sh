#!/bin/sh
#
#  Make openssl s_client send a fatal TLS alert to unit_test_tls, and check
#  that the alert reached the request list as `Alert`.
#
#  alert.sh covers the opposite direction, where FreeRADIUS sends the alert.
#  This test checks the attribute that FreeRADIUS stores, not the octets on
#  the network.  `fr_tls_session_info_cb()` in `src/lib/tls/session.c` copies
#  the level and the description of the alert into the request list, as the
#  `Level` member and the `Description` member of `Alert`.  Policy can then
#  read which alert ended the handshake, instead of reading only the log.
#
#  The script passes `-CAfile "$CERTDIR/client.pem"` to openssl s_client.
#  `client.pem` is an ordinary end-entity certificate, not a certificate
#  authority certificate.  s_client therefore does not find a trusted issuer
#  for the server certificate, and sends the `unknown_ca` alert.  The
#  dictionary names alert 48 `Unknown-CA`.  Using a certificate that is
#  already in `$CERTDIR` keeps the test from depending on the certificates
#  that the host trusts.
#
#  `-verify_return_error` makes s_client send the alert.  Measured, not
#  assumed: without `-verify_return_error`, s_client prints verify error 21
#  and continues, the handshake completes, and unit_test_tls reads no alert.
#
#  A peer can send more than one alert over one handshake.  This test
#  provokes one alert only.  The test checks that one alert arrives as one
#  `Alert`, with both the `Level` member and the `Description` member set.
#  The test does not check what a second alert does to the first `Alert`.
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

LOG="$OUTPUT/alert_recv.log"
RECEIPT="$OUTPUT/alert_recv.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

fail() {
	echo "alert_recv.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "alert_recv.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

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

echo "--- openssl s_client ---" >> "$LOG"

#
#  s_client rejects the server certificate, so s_client exits non-zero on a
#  successful run of this test.  The script ignores the exit status of
#  s_client.
#
echo | openssl s_client -connect "127.0.0.1:$PORT" \
	-cert "$CERTDIR/client.pem" \
	-key "$CERTDIR/client.key" -pass pass:whatever \
	-CAfile "$CERTDIR/client.pem" \
	-verify_return_error >> "$LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

#
#  unit_test_tls must have read the alert.  Without the check below, a run
#  where s_client closes the connection before sending the alert would pass
#  every check that follows.
#
grep -q "Client sent fatal TLS alert (48)" "$LOG" || \
	fail "the server did not read a fatal unknown_ca alert from the client"

#
#  The alert must also reach the request list as `Alert`, with the `Level`
#  member and the `Description` member both set.
#  `share/dictionary/tls/dictionary.freeradius` defines `Alert`, `Level`,
#  `Description`, and the value names that the check below matches.
#
grep -q "Alert = { Level = ::Fatal, Description = ::Unknown-CA }" "$LOG" || \
	fail "the alert was logged but not added to the request list as Alert"

count=$(grep -c "Alert = {" "$LOG")
[ "$count" = "1" ] || fail "expected one Alert in the request list, found $count"

touch "$RECEIPT"
exit 0
