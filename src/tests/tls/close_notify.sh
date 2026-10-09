#!/bin/sh
#
#  Check that a peer which FreeRADIUS refuses after the handshake has finished
#  receives a close_notify, rather than a socket which stops answering.
#
#  FreeRADIUS cannot send an error alert for a refusal made after the
#  handshake has finished, because the record layer is encrypted by then.
#  close_notify is the one record FreeRADIUS can still send.
#  src/lib/tls/alerts.md gives the rule, quotes RFC 9846 Section 6.1, and says
#  what the choice costs.
#
#  The server requires that both ends agree on a protocol through Application
#  Layer Protocol Negotiation (ALPN), and the client does not offer a
#  protocol.  fr_tls_session_alpn_check() therefore refuses the session after
#  the handshake.  Case 3 of alpn.sh drives the same refusal and checks what
#  the server recorded.  This script checks what the client received.  The
#  server's own log cannot show what the client received.
#
#  openssl s_client is the client here, rather than unit_test_tls, because
#  s_client reports which kind of close arrived.  s_client prints "closed" for
#  a close_notify, and prints "DONE" without a "closed" line when the socket
#  closes without a close_notify.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

LOG="$OUTPUT/close_notify_server.log"
CLIENT_LOG="$OUTPUT/close_notify_client.log"
RECEIPT="$OUTPUT/close_notify.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "close_notify.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "close_notify.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

#
#  stdin comes from /dev/null, so that s_client does not send data and does
#  not close the connection.  The server therefore causes every close which
#  s_client reports.  Sending "Q" here would make s_client close first, and
#  the test would pass whatever the server did.
#
export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n unit_test_tls -xx \
	-L 'radius/1.1' -l \
	-e 'openssl s_client -connect "127.0.0.1:$PORT" \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/ca.pem" < /dev/null > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$LOG"; then
	fail "a signal or a failed assertion appears in $LOG"
fi

######################################################################
#
#  What the server did.
#
######################################################################
grep -q "ALPN - Failure, no protocols in common" "$LOG" || \
	fail "the server did not refuse a session which agreed on no protocol"

grep -q "Not sending TLS alert" "$LOG" || \
	fail "the server did not report that it cannot send an alert after the handshake"

grep -q "Sending close_notify" "$LOG" || \
	fail "the server did not report sending close_notify"

#
#  One close_notify is all the peer is owed.  Every fr_tls_connection_process()
#  which runs while the "fail session { ... }" section finishes calls
#  fr_tls_session_close_send().  fr_tls_session_close_send() does not write a
#  second close_notify, because OpenSSL has recorded SSL_SENT_SHUTDOWN.  A
#  missing check of SSL_SENT_SHUTDOWN appears here as several close_notify
#  lines.
#
count=$(grep -c "Sending close_notify" "$LOG")
[ "$count" = "1" ] || fail "expected one close_notify, the server sent $count"

######################################################################
#
#  What the client received.
#
#  The server's log cannot show what the client received.  A server which
#  calls SSL_shutdown() with quiet shutdown on does not write a record, and
#  still logs that the server sent close_notify.  s_client prints "closed"
#  only when a close_notify arrived.
#
######################################################################
grep -q '^closed$' "$CLIENT_LOG" || \
	fail "the client did not report a close_notify, so the connection was truncated"

if grep -q "TLS handshake completed" "$LOG"; then
	fail "the handshake completed, although an agreement was required"
fi

touch "$RECEIPT"
exit 0
