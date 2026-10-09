#!/bin/sh
#
#  Run unit_test_tls over a datagram socket, connect to it with an OpenSSL
#  DTLS client, and check that unit_test_tls wrote its receipt file.
#
#  This is the test which says DTLS works at all.  Everything it exercises
#  that unit_test_tls.sh does not comes from `transport = udp` in dtls.conf:
#  the DTLS method and version mapping, the MTU passed to OpenSSL, the
#  datagram boundaries recorded by the outgoing bio, and the datagram socket
#  in the test program itself.
#
#  unit_test_tls writes the receipt file only when it exits successfully, so
#  the presence of that file is the result of the test.  The exit status of
#  the OpenSSL client is ignored, because s_client exits non-zero for an
#  ordinary close as readily as for a real failure, and so says nothing
#  about whether the handshake worked.
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

LOG="$OUTPUT/dtls.log"
CLIENT_LOG="$OUTPUT/dtls_client.log"
RECEIPT="$OUTPUT/dtls.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "dtls.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG

#
#  -dtls1_2 rather than -dtls, so that a client which defaults to a version
#  the server refuses fails here rather than somewhere less obvious.
#
$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx -r "$RECEIPT" \
	-e 'echo | openssl s_client -dtls1_2 -connect "127.0.0.1:$PORT" \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/ca.pem" > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

if [ ! -e "$RECEIPT" ]; then
	echo "unit_test_tls did not create $RECEIPT"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
fi

exit 0
