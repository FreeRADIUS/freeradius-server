#!/bin/sh
#
#  Run one unit_test_tls as a server and a second unit_test_tls as a client,
#  run two connections between the pair, and check that the second handshake
#  resumed the session that the first handshake stored.
#
#  Both ends have to agree that resumption happened, so the script checks the
#  server log and the client log.  Two connections are the smallest number
#  that can show resumption.  The first connection fills the cache, and the
#  second connection reads the cache.
#
#  Each end stores sessions in an rlm_cache instance with the rbtree driver,
#  which keeps them in the memory of the process.  A second server process
#  would start with an empty cache, so one server process serves both
#  connections.
#
#  Each program writes a receipt file only when that program exits
#  successfully.  A receipt therefore records that the connections worked,
#  and one "resumed    : yes" line in each log records that the caching
#  worked.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding unit_test_tls.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the cache configuration for both ends is in
#  src/tests/tls/unit_test_tls.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/session_cache_server.log"
CLIENT_LOG="$OUTPUT/session_cache_client.log"
SERVER_RECEIPT="$OUTPUT/session_cache_server.receipt"
CLIENT_RECEIPT="$OUTPUT/session_cache_client.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT"

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

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 \
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

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 -s "127.0.0.1:$PORT" \
	-r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

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

exit 0
