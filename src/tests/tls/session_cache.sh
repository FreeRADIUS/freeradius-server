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
RECEIPT="$OUTPUT/session_cache.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

export CLIENT_LOG CLIENT_RECEIPT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 \
	-r "$SERVER_RECEIPT" \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 -s "127.0.0.1:$PORT" \
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
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
