#!/bin/sh
#
#  Run one unit_test_tls as a DTLS server and a second as a DTLS client, run
#  two connections between the pair, and check that the second handshake
#  resumed the session that the first handshake stored.
#
#  This is session_cache.sh over a datagram transport.  It is a separate test
#  rather than a transport argument to that one, because the two differ in
#  what they prove: this one also exercises the client side of the datagram
#  socket, which nothing else does.  Every other DTLS test uses
#  `openssl s_client`, so unit_test_tls has only ever been the server.
#
#  Only stateful resumption is possible here.  fr_tls_ctx_alloc() refuses
#  `mode = "stateless"` for a datagram context and rewrites `mode = "auto"`
#  to stateful, so a resumed DTLS session is always a stateful one.
#
#  Both ends have to agree that resumption happened, so the script checks the
#  server log and the client log.  Two connections are the smallest number
#  that can show resumption: the first fills the cache, the second reads it.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding dtls.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  $Id$
#

SERVER_LOG="$OUTPUT/dtls_resume_server.log"
CLIENT_LOG="$OUTPUT/dtls_resume_client.log"
SERVER_RECEIPT="$OUTPUT/dtls_resume_server.receipt"
CLIENT_RECEIPT="$OUTPUT/dtls_resume_client.receipt"
RECEIPT="$OUTPUT/dtls_resume.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

export CLIENT_LOG CLIENT_RECEIPT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx -c 2 \
	-r "$SERVER_RECEIPT" \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n dtls -xx -c 2 -s "127.0.0.1:$PORT" \
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

#
#  Exactly one of the two connections must report a resumed session, and both
#  ends must report the resumption.
#
for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	count=$(grep -c "resumed    : yes" "$log")
	[ "$count" = "1" ] || fail "expected one resumed session in $log, found $count"
done

#
#  Both ends have to have been speaking DTLS, not TLS over a stream.  The
#  check is cheap and the mistake would be invisible otherwise: the test
#  would pass just as well with `transport = tcp`.
#
for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	grep -q "using udp" "$log" || grep -q "Connection is DTLS" "$log" || \
		fail "$log does not show a datagram transport"
done

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
