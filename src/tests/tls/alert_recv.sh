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
CLIENT_LOG="$OUTPUT/alert_recv_client.log"
RECEIPT="$OUTPUT/alert_recv.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "alert_recv.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "alert_recv.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

#
#  s_client writes to its own file.  unit_test_tls is still writing to $LOG
#  at this point, and two programs writing to one file overwrite each other,
#  which loses whichever lines land in the gap.
#
#  s_client rejects the server certificate, so s_client exits non-zero on a
#  successful run of this test.  The script ignores the exit status of
#  s_client.
#
export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx \
	-e 'echo | openssl s_client -connect "127.0.0.1:$PORT" \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/client.pem" \
		-verify_return_error > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

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

count=$(grep -c "Adding Alert = {" "$LOG")
[ "$count" = "1" ] || fail "expected one Alert in the request list, found $count"

#
#  A received alert must not appear in the reply list.  The list which holds
#  the alert is the only thing which says which end sent the alert, so a
#  received alert showing up in both lists would make the signal useless.
#
if grep -q "reply.Alert = {" "$LOG"; then
	fail "a received alert was also put in the reply list"
fi

#
#  `Error` says what went wrong.  `Received-Alert` is the value which tells
#  an administrator to look in the request list.
#
grep -q "request.Error = ::Received-Alert" "$LOG" || \
	fail "the Received-Alert error was not added to the session-state list"

#
#  What `fail session { ... }` can read is checked in reject.sh rather than
#  here.  Both scripts reach the section now that fr_tls_connection_failed()
#  defers a failure while a record is still waiting for OpenSSL, but reject.sh
#  runs unit_test_tls at both ends, so it keeps the check away from whatever
#  openssl s_client does when it closes.
#
touch "$RECEIPT"
exit 0
