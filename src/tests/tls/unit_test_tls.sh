#!/bin/sh
#
#  Run unit_test_tls, connect to it with an OpenSSL client, and check that
#  unit_test_tls wrote its receipt file.
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
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  $Id$
#

LOG="$OUTPUT/unit_test_tls.log"
CLIENT_LOG="$OUTPUT/unit_test_tls_client.log"
RECEIPT="$OUTPUT/unit_test_tls.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "unit_test_tls.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -r "$RECEIPT" \
	-e 'echo | openssl s_client -connect "127.0.0.1:$PORT" \
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
