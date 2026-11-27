#!/bin/sh
#
#  Run one connection with TLS 1.2 and one with TLS 1.3.  On each connection
#  both ends have `buffer_size = 2048`, and the server sends a certificate of
#  about 64K.  Check that both handshakes complete.
#
#  The buffer that holds the octets read from the peer (`dirty_in`) is never
#  smaller than one maximum-size TLS record.  See
#  `tls_session_set_buffer_sizes()` in `src/lib/tls/session.c`.  Because
#  `buffer_size = 2048` is below that minimum, `dirty_in` holds one record.
#  The server's Certificate message is about four TLS records long.  The test
#  checks that the client reads the Certificate message without overflowing
#  `dirty_in`.
#
#  The script creates a new key and a server certificate in the output
#  directory, and signs the certificate with the test CA.  The certificate
#  carries one private extension holding 65000 octets of filler.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding big_cert.conf
#    CERTDIR        directory holding the test CA
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/big_cert.conf.
#
#  $Id$
#

RECEIPT="$OUTPUT/big_cert.receipt"
BIG_CERT="$OUTPUT/big_cert.pem"
BIG_KEY="$OUTPUT/big_cert.key"
BIG_EXT="$OUTPUT/big_cert.ext"
BIG_CSR="$OUTPUT/big_cert.csr"
OPENSSL_LOG="$OUTPUT/big_cert_openssl.log"

mkdir -p "$OUTPUT"
rm -f "$RECEIPT" "$BIG_CERT" "$BIG_KEY" "$BIG_EXT" "$BIG_CSR" "$OPENSSL_LOG"

fail() {
	echo "big_cert.sh: $1"
	[ -n "$SERVER_LOG" ] && { echo "--- $SERVER_LOG ---"; cat "$SERVER_LOG"; }
	[ -n "$CLIENT_LOG" ] && { echo "--- $CLIENT_LOG ---"; cat "$CLIENT_LOG"; }
	exit 1
}

if [ ! -r "$CERTDIR/ca.key" ]; then
	echo "big_cert.sh: no CA key in $CERTDIR, run 'make certs'"
	exit 1
fi

#
#  `od` writes the 65000 octets of filler as hex, inside an OCTET STRING.  The
#  Object Identifier (OID) is under the FreeRADIUS private enterprise number.
#  Because the extension is not marked critical, the client ignores the
#  extension.
#
{
	echo "[big]"
	echo "basicConstraints = CA:FALSE"
	echo "extendedKeyUsage = serverAuth"
	printf "1.3.6.1.4.1.11344.255.1 = ASN1:FORMAT:HEX,OCTETSTRING:"
	head -c 65000 /dev/zero | od -An -v -tx1 | tr -d ' \n'
	echo
} > "$BIG_EXT"

openssl req -new -newkey rsa:2048 -nodes -keyout "$BIG_KEY" -out "$BIG_CSR" \
	-subj "/C=FR/ST=Radius/O=Example Inc./CN=Example Server Certificate" \
	>> "$OPENSSL_LOG" 2>&1 || { cat "$OPENSSL_LOG"; fail "failed creating the key"; }

openssl x509 -req -in "$BIG_CSR" -CA "$CERTDIR/ca.pem" -CAkey "$CERTDIR/ca.key" \
	-passin pass:whatever -CAcreateserial -CAserial "$OUTPUT/big_cert.srl" -days 2 \
	-extfile "$BIG_EXT" -extensions big -out "$BIG_CERT" \
	>> "$OPENSSL_LOG" 2>&1 || { cat "$OPENSSL_LOG"; fail "failed signing the certificate"; }

size=$(openssl x509 -in "$BIG_CERT" -outform DER | wc -c | tr -d ' ')
[ "$size" -gt 65000 ] || fail "the certificate is only $size octets"

export BIG_CERT BIG_KEY

for TLS_VERSION in 1.2 1.3; do
	SERVER_LOG="$OUTPUT/big_cert_${TLS_VERSION}_server.log"
	CLIENT_LOG="$OUTPUT/big_cert_${TLS_VERSION}_client.log"
	SERVER_RECEIPT="$OUTPUT/big_cert_${TLS_VERSION}_server.receipt"
	CLIENT_RECEIPT="$OUTPUT/big_cert_${TLS_VERSION}_client.receipt"

	rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT"

	export TLS_VERSION CLIENT_LOG CLIENT_RECEIPT

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n big_cert -xx -c 1 \
		-r "$SERVER_RECEIPT" \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n big_cert -xx -c 1 \
			-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1' \
		> "$SERVER_LOG" 2>&1

	[ -e "$SERVER_RECEIPT" ] || fail "TLS $TLS_VERSION: server did not create $SERVER_RECEIPT"
	[ -e "$CLIENT_RECEIPT" ] || fail "TLS $TLS_VERSION: client did not create $CLIENT_RECEIPT"

	for log in "$SERVER_LOG" "$CLIENT_LOG"; do
		count=$(grep -c "TLS handshake completed" "$log")
		[ "$count" = "1" ] || fail "TLS $TLS_VERSION: expected one completed handshake in $log, found $count"

		if grep -q "Failed buffering" "$log"; then
			fail "TLS $TLS_VERSION: the receive buffer overflowed in $log"
		fi

		if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
			fail "TLS $TLS_VERSION: a signal or a failed assertion appears in $log"
		fi
	done
done

touch "$RECEIPT"
exit 0
