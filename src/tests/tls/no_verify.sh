#!/bin/sh
#
#  Run one connection between a server and a client whose virtual server has
#  no `verify certificate` section, and check that both ends still decoded the
#  peer's chain into `session-state.TLS-Certificate` pairs.
#
#  The verify callback runs on OpenSSL's fibre, which has a limited stack, so
#  the TLS code decodes the chain on the main stack after the callback has
#  paused the handshake.  Every other test in this directory has a
#  `verify certificate` section, so the pause always has a section to run.
#  This test is the case where the pause is for the decode alone: the chain
#  is decoded, nothing is pushed, and the handshake resumes.  See
#  fr_tls_verify_cert_pending_push() in src/lib/tls/verify.c.
#
#  Each program writes a receipt file only when that program exits
#  successfully, so a receipt records that the connection worked and that
#  nothing aborted on the way out.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding no_verify.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/no_verify.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/no_verify_server.log"
CLIENT_LOG="$OUTPUT/no_verify_client.log"
SERVER_RECEIPT="$OUTPUT/no_verify_server.receipt"
CLIENT_RECEIPT="$OUTPUT/no_verify_client.receipt"
RECEIPT="$OUTPUT/no_verify.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

#
#  setsid puts the server in a new session and process group, so that
#  signalling the process group reaches the server and every process the
#  server started.  "session" here is the process kind, not the TLS kind.
#  Not every system has setsid, macOS for one, so fall back to running the
#  server without setsid.  The trap below kills the server either way.
#
if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_verify -xx -c 1 \
	-r "$SERVER_RECEIPT" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

#
#  Wait until the server logs "Waiting for a connection".  The log line says
#  the listening socket is open, so the client connects as soon as the server
#  is ready rather than after a guessed delay.  The loop bounds the wait, so a
#  server that never opens the socket fails the test rather than hanging it.
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

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_verify -xx -c 1 \
	-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

fail() {
	echo "$1"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

#
#  A receipt is written on a clean exit only, so a missing receipt is how a
#  failed assertion in the verify code shows up.
#
[ -e "$SERVER_RECEIPT" ] || fail "server did not create $SERVER_RECEIPT"
[ -e "$CLIENT_RECEIPT" ] || fail "client did not create $CLIENT_RECEIPT"

for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	#
	#  The connection must complete.  A missing section changes what
	#  runs while the handshake is paused, not whether the handshake works.
	#
	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "1" ] || fail "expected one completed handshake in $log, found $count"

	#
	#  The handshake must have paused for the decode.
	#
	grep -q "Decoding certificate chain" "$log" || fail "the chain was not decoded in $log"

	#
	#  `attribute_mode = client-and-issuer` decodes the peer's certificate
	#  and its issuer, so two `TLS-Certificate` pairs.  The TLS code logs
	#  each one as it is decoded.
	#
	count=$(grep -c "^(.*)  session-state.TLS-Certificate = {" "$log")
	[ "$count" = "2" ] || fail "expected two decoded certificates in $log, found $count"

	#
	#  Nothing may have been pushed.  The virtual server has no
	#  `verify certificate` section, so one running is a real fault.
	#
	if grep -q "Requesting certificate validation" "$log"; then
		fail "certificate validation was requested in $log, with no 'verify certificate' section"
	fi

	if grep -q "^(.*)  *verify certificate {" "$log"; then
		fail "'verify certificate' ran in $log, with no such section"
	fi

	#
	#  Nothing may have crashed on the way through.
	#
	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$log"; then
		fail "a signal or a failed assertion appears in $log"
	fi
done

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
