#!/bin/sh
#
#  Run two connections between a server and a client, let the second connection
#  resume the session the first one stored, then reject it, and check that
#  clear session { ... } removed the entry.
#
#  This is the case fr_tls_cache_clear_session() treats differently from every
#  other failure.  A session which was never loaded was never in the cache,
#  because store session { ... } does not run on a failed session, so the clear
#  is dropped.  A session which was loaded is still in the cache after the
#  handshake fails, because load session { ... } reads an entry without
#  removing it, so the clear has to run.  reject.sh covers the first case, and
#  this script covers the second.
#
#  Two connections are the smallest number that can show it.  The first
#  connection stores.  The second resumes, and -R rejects it once the handshake
#  has succeeded, which is the point at which a session has been loaded and a
#  failure still has to clean up after it.
#
#  -R only rejects the last connection, so the first connection completes and
#  stores normally.  Both ends run one process each, because an rlm_cache
#  rbtree instance lives in the memory of the process which created it, and a
#  second server process would start with an empty cache.
#
#  The server exits non-zero, having failed a session on purpose, so the server
#  is not asked for a receipt.  This script writes the receipt once the server
#  log says what it should.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the cache configuration for both ends is in
#  src/tests/tls/common.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/fail_resumed_server.log"
CLIENT_LOG="$OUTPUT/fail_resumed_client.log"
RECEIPT="$OUTPUT/fail_resumed.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$RECEIPT"

export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 -R \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -c 2 \
		-s "127.0.0.1:$PORT" > "$CLIENT_LOG" 2>&1' \
	> "$SERVER_LOG" 2>&1

fail() {
	echo "$1"
	echo "--- $SERVER_LOG ---"
	cat "$SERVER_LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

#
#  The first connection has to store, or the second has nothing to resume and
#  the test proves nothing.
#
count=$(grep -c "# store session" "$SERVER_LOG")
[ "$count" = "1" ] || fail "expected one store session, found $count"

#
#  The second connection has to resume, which is what sets the flag that
#  decides whether the clear runs.
#
count=$(grep -c "resumed    : yes" "$SERVER_LOG")
[ "$count" = "1" ] || fail "expected one resumed session, found $count"

#
#  -R fails the session after that, so fail session { ... } runs.
#
grep -q "Rejecting the session after a successful handshake" "$SERVER_LOG" || \
	fail "the server did not reject the session, -R had no effect"

grep -q "# fail session" "$SERVER_LOG" || \
	fail "fail session did not run, so the failure path was not reached"

#
#  And the clear runs, because the session which failed came out of the cache.
#  This is the assertion the whole script exists for.
#
grep -q "# clear session" "$SERVER_LOG" || \
	fail "clear session did not run, although the failed session was loaded from the cache"

if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$SERVER_LOG"; then
	fail "a signal or a failed assertion appears in $SERVER_LOG"
fi

touch "$RECEIPT"
exit 0
