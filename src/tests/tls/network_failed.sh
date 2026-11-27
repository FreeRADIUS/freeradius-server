#!/bin/sh
#
#  Run two connections between a server and a client, and fail the second connection with a
#  network error:
#
#    1. The first connection stores a session.
#    2. The second connection resumes the session that the first connection stored.
#    3. `-N` fails the second connection with `TLS_CONNECTION_FAIL_SYSCALL` once the handshake has
#       succeeded.
#    4. The script checks that `clear session { ... }` does not run, and that `store session { ... }`
#       does not run for the second connection.
#
#  A network error says nothing about the cached session.  The peer may resume the cached session
#  on a later connection.  `reject.sh` and `fail_resumed.sh` cover the failures that do clear the
#  cached session.
#
#  The same failure handling runs as when the peer closes the connection.  `fail session { ... }`
#  runs after a network failure, as after every other failure.
#
#  The script runs the two connections twice.  The first run uses TLS 1.2, and the second run uses
#  TLS 1.3, where the server also gives the resumed connection a new ticket.  Because an `rlm_cache`
#  rbtree lives in the memory of the process that created the rbtree, the server and the client each
#  run as one process.
#
#  The server fails a session on purpose, and the server exits with a non-zero status.  Because of
#  that status, the script does not ask the server to write a receipt file.  The script writes
#  `network_failed.receipt` after the server log contains the lines that the checks in `run()` look
#  for.
#
#  Environment:
#    UNIT_TEST_TLS  command line that runs `unit_test_tls`, which may contain several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding `unit_test_tls.conf`
#    DICT_PATH      dictionary directory
#    PORT           port that `unit_test_tls` listens on
#
#  `make test.tls` sets every variable above and runs `network_failed.sh`.  The `test.tls` recipe is
#  in `src/tests/tls/all.mk`, and the cache configuration for both ends is in
#  `src/tests/tls/common.conf`.
#
#  $Id$
#

mkdir -p "$OUTPUT"

fail() {
	echo "$1"
	for f in "$OUTPUT"/network_failed_*.log; do
		[ -e "$f" ] || continue
		echo "--- $f ---"
		cat "$f"
	done
	exit 1
}

#
#  run <case name> <name of the -n configuration> <TLS version in the server log>
#
run() {
	name="$1"
	conf="$2"
	version="$3"

	SERVER_LOG="$OUTPUT/network_failed_${name}_server.log"
	CLIENT_LOG="$OUTPUT/network_failed_${name}_client.log"

	rm -f "$SERVER_LOG" "$CLIENT_LOG"

	export CLIENT_LOG conf

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 -N \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 \
			-s "127.0.0.1:$PORT" > "$CLIENT_LOG" 2>&1' \
		> "$SERVER_LOG" 2>&1

	#
	#  The first connection has to store the session.  If the first connection does not store a
	#  session, the second connection has nothing to resume, and the checks below do not exercise a
	#  loaded session.  The second connection must not run `store session { ... }`, even though a
	#  TLS 1.3 server asks to store the new ticket of the second connection.
	#
	count=$(grep -c "# store session" "$SERVER_LOG")
	[ "$count" = "1" ] || fail "$name: expected one store session, found $count"

	count=$(grep -c "version    : $version" "$SERVER_LOG")
	[ "$count" = "2" ] || fail "$name: expected two $version connections, found $count"

	#
	#  The second connection has to resume the session, because only resumption loads a session.
	#
	count=$(grep -c "resumed    : yes" "$SERVER_LOG")
	[ "$count" = "1" ] || fail "$name: expected one resumed session, found $count"

	grep -q "Failing, with a network error, the session" "$SERVER_LOG" || \
		fail "$name: the server did not fail the session, -N had no effect"

	#
	#  Because `fail session { ... }` runs for every failure, the check below proves that the server
	#  reached the failure path.
	#
	grep -q "# fail session" "$SERVER_LOG" || \
		fail "$name: fail session did not run, so the failure path was not reached"

	#
	#  A network error must not run `clear session { ... }`, because the cached session stays valid
	#  for the peer to resume.
	#
	if grep -q "# clear session" "$SERVER_LOG"; then
		fail "$name: clear session ran after a network failure"
	fi

	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$SERVER_LOG"; then
		fail "$name: a signal or a failed assertion appears in $SERVER_LOG"
	fi
}

run tls12 unit_test_tls "TLSv1.2"
run tls13 stateful_tls13 "TLSv1.3"

touch "$OUTPUT/network_failed.receipt"
exit 0
