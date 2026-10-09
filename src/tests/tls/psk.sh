#!/bin/sh
#
#  Run one connection authenticated with a pre-shared key (PSK), where the
#  server finds the key with the `load psk` section of its virtual server.
#
#  The server log must show the section running, and both ends must
#  complete the handshake over a PSK cipher.  `psk.conf` explains why the
#  section runs on the request's stack rather than in the callback.
#
#  The server and the client each write a receipt file only on a
#  successful exit, so a receipt records that the connection worked.  The
#  test writes out the receipt itself, so that if a crash causes an early
#  exit the error is flagged by the make framework.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding psk.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  `make test.tls` sets every variable above and runs this script.  The recipe
#  is in `src/tests/tls/all.mk`, and the configuration is in
#  `src/tests/tls/psk.conf`.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/psk_server.log"
CLIENT_LOG="$OUTPUT/psk_client.log"
SERVER_RECEIPT="$OUTPUT/psk_server.receipt"
CLIENT_RECEIPT="$OUTPUT/psk_client.receipt"
RECEIPT="$OUTPUT/psk.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

export CLIENT_LOG CLIENT_RECEIPT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n psk -xx \
	-r "$SERVER_RECEIPT" \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n psk -xx \
		-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1' \
	> "$SERVER_LOG" 2>&1

fail() {
	echo "psk.sh: $1"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

[ -e "$SERVER_RECEIPT" ] || fail "server did not create $SERVER_RECEIPT"
[ -e "$CLIENT_RECEIPT" ] || fail "client did not create $CLIENT_RECEIPT"

for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "1" ] || fail "expected one completed handshake in $log, found $count"

	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
		fail "a signal or a failed assertion appears in $log"
	fi
done

#
#  The configuration offers only PSK ciphers.  The cipher that the two
#  ends agreed on therefore proves that the server found the key and that
#  the keys matched.
#
grep -q "cipher     : .*PSK" "$SERVER_LOG" || \
	fail "the server did not negotiate a PSK cipher"

#
#  The section must have run from tls_session_async_handshake_cont()
#  rather than from inside the callback.  The identity that the client
#  sent must also have reached the subrequest, because the section reads
#  the identity from the request.
#
grep -q "Loading the pre-shared key for identity \"0123456789abcdef0123456789abcdef\"" "$SERVER_LOG" || \
	fail "tls_session_async_handshake_cont() did not call load psk"

grep -q "^(.*)  *load psk {" "$SERVER_LOG" || \
	fail "the load psk section did not run"

grep -q "Loaded a 16-byte pre-shared key" "$SERVER_LOG" || \
	fail "load psk did not return the 16-byte key"

touch "$RECEIPT"
exit 0
