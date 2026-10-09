#!/bin/sh
#
#  Run two DTLS handshakes against one listening socket, from two different
#  source ports.
#
#  The point of the test is the listening socket, not the handshakes.  A
#  datagram connection runs on a second socket which is connect()ed to the
#  peer.  connect() is a property of the socket rather than of the
#  descriptor, so connecting the listening socket, or any descriptor
#  duplicated from it, would bind the listening socket to the first peer for
#  the rest of the program.  The first handshake would still succeed, and the
#  second would never be heard.  One connection cannot tell the two
#  arrangements apart, which is why this test runs two.
#
#  Environment:
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding dtls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  $Id$
#

LOG="$OUTPUT/dtls_two.log"
CLIENT_LOG="$OUTPUT/dtls_two_client.log"
RECEIPT="$OUTPUT/dtls_two.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "dtls_two.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG

#
#  -c 2 runs two connections.  Each s_client gets a source port of its own,
#  so the second handshake arrives from an address the listening socket has
#  not heard from before.
#
$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx -c 2 -r "$RECEIPT" \
	-e 'for i in 1 2; do
		echo | openssl s_client -dtls1_2 -connect "127.0.0.1:$PORT" \
			-cert "$CERTDIR/client.pem" \
			-key "$CERTDIR/client.key" -pass pass:whatever \
			-CAfile "$CERTDIR/ca.pem" >> "$CLIENT_LOG" 2>&1
	done' \
	> "$LOG" 2>&1

if [ ! -e "$RECEIPT" ]; then
	echo "unit_test_tls did not create $RECEIPT"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
fi

#
#  The receipt says the program exited cleanly.  It does not say that both
#  handshakes ran, which is the thing this test is about.
#
count=$(grep -c "TLS handshake completed" "$LOG")
if [ "$count" -ne 2 ]; then
	echo "dtls_two.sh: expected 2 completed handshakes, found $count"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
fi

exit 0
