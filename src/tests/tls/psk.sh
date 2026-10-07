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

#
#  setsid puts the server in a new session and process group, so that
#  signalling the process group reaches the server and every process that
#  the server started.  Not every system has setsid, so the script falls
#  back to running the server without setsid.  The trap below kills the
#  server either way.
#
if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n psk -xx \
	-r "$SERVER_RECEIPT" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

#
#  The loop waits until the server logs "Waiting for a connection".  The log
#  line says that the listening socket is open, so the client connects as
#  soon as the server is ready rather than after a guessed delay.  The loop
#  bounds the wait, so a server that never opens the socket fails the test
#  rather than hanging the test.
#
if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$SERVER_LOG" 2> /dev/null && break

	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n psk -xx \
	-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

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
