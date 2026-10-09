#!/bin/sh
#
#  Check that the DTLS server demands a cookie before it does handshake work.
#
#  The handshake succeeds whether or not the server asked for a cookie, so a
#  receipt says nothing about it.  This test reads the log for the exchange
#  itself: a ClientHello, a HelloVerifyRequest carrying the cookie, and a
#  second ClientHello which echoes it back.
#
#  RFC 6347 Section 4.2.1 says a server SHOULD perform the exchange by
#  default.  Without it a forged source address can make the server do the
#  work of a handshake, which is what makes an unprotected DTLS server useful
#  to somebody else as an amplifier.
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

LOG="$OUTPUT/dtls_cookie.log"
CLIENT_LOG="$OUTPUT/dtls_cookie_client.log"
RECEIPT="$OUTPUT/dtls_cookie.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "dtls_cookie.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG

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
	exit 1
fi

#
#  One HelloVerifyRequest, and two ClientHellos: the first without a cookie
#  and the second with one.
#
hvr=$(grep -c "hello_verify_request" "$LOG")
hello=$(grep -c "client_hello" "$LOG")

if [ "$hvr" -ne 1 ] || [ "$hello" -ne 2 ]; then
	echo "dtls_cookie.sh: expected 1 hello_verify_request and 2 client_hello,"
	echo "                found $hvr and $hello"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
fi

exit 0
