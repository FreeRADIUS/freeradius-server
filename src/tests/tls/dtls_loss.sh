#!/bin/sh
#
#  Throw away one datagram of a DTLS handshake, and check that the handshake
#  completes anyway.
#
#  dtls_loss.sh is the only test which reaches the retransmission timer.
#  Every other DTLS test runs over loopback, which loses nothing, so the
#  library arms and disarms the timer, and the timer never fires.  Without
#  dtls_loss.sh, no test runs the code which recovers from loss.
#
#  The client runs dtls_loss.conf, which drops the third datagram the client
#  sends.  The dropped datagram belongs to the flight the server is waiting
#  for, so the server's retransmission timer fires and the server resends the
#  flight the server already sent.  The client then answers, and the
#  handshake finishes.
#
#  A receipt alone shows only that both ends finished the handshake, so the
#  test reads the two logs as well.  The test checks three facts:
#
#    1.  The client dropped the datagram.
#    2.  The server's retransmission timer fired.
#    3.  Both ends finished the handshake.
#
#  The test does not cover the doubling backoff of RFC 6347 Section 4.2.4.1.
#  Recovering one lost datagram needs the timer to fire once, so a library
#  which arms the timer once and never re-arms the timer passes this test.
#  Covering the backoff needs a second dropped datagram, which has to be the
#  retransmission of the first.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding dtls.conf and dtls_loss.conf
#    DICT_PATH      dictionary directory
#    PORT           port that unit_test_tls listens on
#
#  The test takes over a second to run.  RFC 6347 Section 4.2.4.1 sets the
#  first retransmission interval at one second, and the server waits that
#  long before the server resends.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/dtls_loss_server.log"
CLIENT_LOG="$OUTPUT/dtls_loss_client.log"
SERVER_RECEIPT="$OUTPUT/dtls_loss_server.receipt"
CLIENT_RECEIPT="$OUTPUT/dtls_loss_client.receipt"
RECEIPT="$OUTPUT/dtls_loss.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

export CLIENT_LOG CLIENT_RECEIPT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx \
	-r "$SERVER_RECEIPT" \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls_loss -xx -s "127.0.0.1:$PORT" \
		-r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1' \
	> "$SERVER_LOG" 2>&1

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

dropped=$(grep -c "Dropping datagram" "$CLIENT_LOG")
[ "$dropped" = "1" ] || fail "expected the client to drop one datagram, it dropped $dropped"

fired=$(grep -c "retransmission timer fired" "$SERVER_LOG")
[ "$fired" -ge 1 ] || fail "the server's retransmission timer did not fire"

completed=$(grep -c "TLS handshake completed" "$SERVER_LOG")
[ "$completed" = "1" ] || fail "expected one completed handshake, found $completed"

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
