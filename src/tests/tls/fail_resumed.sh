#!/bin/sh
#
#  Run two connections between a server and a client.  Let the second connection resume the
#  session that the first connection stored, then reject the second connection.  Check that
#  `clear session { ... }` removed the cache entry.
#
#  `fr_tls_ticket_stateful_clear_session()` treats one case differently from every other failure.
#  Because `store session { ... }` does not run on a failed session, a session which was never
#  loaded was never in the cache, and the clear is dropped.  Because `load session { ... }` reads
#  an entry without removing the entry, a session which was loaded is still in the cache after the
#  handshake fails, and the clear has to run.  `reject.sh` covers the first case, and
#  `fail_resumed.sh` covers the second.
#
#  Two connections are the smallest number that can show the difference.  The first connection
#  stores the session.  The second connection then resumes the session, and `-R` rejects the
#  second connection once the handshake has succeeded.  At that point the server has loaded a
#  session, and a failure still has to clear the loaded session.
#
#  `-R` rejects only the last connection.  The first connection completes and stores the session
#  normally.  Both ends run one process each, because an `rlm_cache` rbtree lives in the memory of
#  the process which created the rbtree, and a second server process would start with an empty
#  cache.
#
#  The server exits with a non-zero status, because the server fails a session on purpose.
#  Because of that status, the script does not ask the server for a receipt.  The script writes
#  `fail_resumed.receipt` after the server log contains the expected lines.
#
#  The script runs the two connections twice.  The first run uses TLS 1.2, where the resumed
#  session keeps the session ID of the loaded session.  The second run uses TLS 1.3, where the
#  server also gives the resumed connection a new ticket with a new session ID.  The new session ID
#  is never stored, because the connection fails.  `clear session { ... }` has to name the ID of
#  the loaded session, and not the new session ID.  Otherwise the loaded session stays in the
#  cache.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs `unit_test_tls`, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding `unit_test_tls.conf`
#    DICT_PATH      dictionary directory
#    PORT           port that `unit_test_tls` listens on
#
#  `make test.tls` sets every variable above and runs `fail_resumed.sh`.  The recipe is in
#  `src/tests/tls/all.mk`, and the cache configuration for both ends is in
#  `src/tests/tls/common.conf`.
#
#  $Id$
#

mkdir -p "$OUTPUT"

fail() {
	echo "$1"
	for f in "$OUTPUT"/fail_resumed_*.log; do
		[ -e "$f" ] || continue
		echo "--- $f ---"
		cat "$f"
	done
	exit 1
}

#
#  run <case> <config name> <TLS version in the log>
#
run() {
	name="$1"
	conf="$2"
	version="$3"

	SERVER_LOG="$OUTPUT/fail_resumed_${name}_server.log"
	CLIENT_LOG="$OUTPUT/fail_resumed_${name}_client.log"

	rm -f "$SERVER_LOG" "$CLIENT_LOG"

	export CLIENT_LOG conf

	$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xxx -c 2 -R \
		-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n "$conf" -xx -c 2 \
			-s "127.0.0.1:$PORT" > "$CLIENT_LOG" 2>&1' \
		> "$SERVER_LOG" 2>&1

	#
	#  The first connection has to store the session.  Otherwise the second connection has nothing to
	#  resume, and the test proves nothing.  A TLS 1.3 server also creates a new ticket for the second
	#  connection, but `-R` fails the second connection before `store session { ... }` runs for that
	#  ticket.
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

	#
	#  Because `-R` fails the session after the handshake succeeds, `fail session { ... }` runs.
	#
	grep -q "Rejecting the session after a successful handshake" "$SERVER_LOG" || \
		fail "$name: the server did not reject the session, -R had no effect"

	grep -q "# fail session" "$SERVER_LOG" || \
		fail "$name: fail session did not run, so the failure path was not reached"

	#
	#  `clear session { ... }` runs once, because the session which failed was loaded from the cache.
	#
	count=$(grep -c "# clear session" "$SERVER_LOG")
	[ "$count" = "1" ] || fail "$name: expected one clear session, found $count, although the failed session was loaded from the cache"

	#
	#  `clear session { ... }` has to use the ID of the session that the second connection loaded.
	#
	load_id=$(sed -nE 's/.*Requested session load - ID (0x[0-9a-fA-F]+).*/\1/p' "$SERVER_LOG")
	clear_id=$(sed -nE 's/.*Session ID (0x[0-9a-fA-F]+) - Requested session clear.*/\1/p' "$SERVER_LOG")

	[ -n "$load_id" ] || fail "$name: the server log has no load session ID"
	[ -n "$clear_id" ] || fail "$name: the server log has no clear session ID"
	[ "$clear_id" = "$load_id" ] || fail "$name: clear session used ID $clear_id, the loaded session is $load_id"

	#
	#  TLS 1.3 gives the second connection a ticket with a new session ID.  A clear that used the ID
	#  of the new ticket would differ from the loaded ID.  Make sure that the new ticket exists,
	#  because without the new ticket the check above cannot tell the loaded ID from the new ID.
	#
	if [ "$version" = "TLSv1.3" ]; then
		new_ids=$(sed -nE 's/.*Session ID (0x[0-9a-fA-F]+) - Requested store.*/\1/p' "$SERVER_LOG" | grep -vc "^$load_id\$")
		[ "$new_ids" -ge 1 ] || fail "$name: the second connection has no new ticket, so the test cannot tell the two IDs apart"
	fi

	if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$SERVER_LOG"; then
		fail "$name: a signal or a failed assertion appears in $SERVER_LOG"
	fi
}

run tls12 unit_test_tls "TLSv1.2"
run tls13 stateful_tls13 "TLSv1.3"

touch "$OUTPUT/fail_resumed.receipt"
exit 0
