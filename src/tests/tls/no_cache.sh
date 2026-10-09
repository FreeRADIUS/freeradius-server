#!/bin/sh
#
#  Run two connections between a server and a client which both have session
#  caching turned off, and check that neither end resumed, and that neither
#  end crashed.
#
#  Every other test in this directory runs with caching on.  With
#  `mode = disabled` the TLS code allocates no fr_tls_cache_t, so
#  tls_session->cache stays NULL, and several places take a NULL path that no
#  other test reaches: fr_tls_ticket_stateful_pending() in src/lib/tls/ticket.h, and
#  fr_tls_cache_disable(), fr_tls_cache_clear_session() and
#  fr_tls_cache_deny() in src/lib/tls/ticket_stateful.c.  A missing NULL check in any of
#  them is a null dereference rather than a wrong answer, so the check that
#  matters most here is simply that both programs exited cleanly.
#
#  Two connections rather than one, for two reasons.  The second connection is
#  where a stored session would be offered, so two connections are what proves
#  caching is really off rather than merely unexercised.  Two connections also
#  run the session teardown twice, and the teardown is where
#  fr_tls_ticket_stateful_pending() is asserted on.
#
#  The configuration still has `load session`, `store session` and
#  `clear session` sections, in common.conf.  Leaving them there is the point.
#  A configuration which names cache sections but disables caching must not
#  call them, and the script checks that none of them ran.
#
#  Each program writes a receipt file only when that program exits
#  successfully, so a receipt records that the connections worked and that
#  nothing aborted on the way out.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt files
#    CONFDIR        directory holding no_cache.conf
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk, and the configuration is in
#  src/tests/tls/no_cache.conf.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/no_cache_server.log"
CLIENT_LOG="$OUTPUT/no_cache_client.log"
SERVER_RECEIPT="$OUTPUT/no_cache_server.receipt"
CLIENT_RECEIPT="$OUTPUT/no_cache_client.receipt"
RECEIPT="$OUTPUT/no_cache.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$SERVER_RECEIPT" "$CLIENT_RECEIPT" "$RECEIPT"

export CLIENT_LOG CLIENT_RECEIPT

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_cache -xx -c 2 \
	-r "$SERVER_RECEIPT" \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_cache -xx -c 2 \
		-s "127.0.0.1:$PORT" -r "$CLIENT_RECEIPT" > "$CLIENT_LOG" 2>&1' \
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
#  A receipt is written on a clean exit only, so a missing receipt is how a
#  null dereference or a failed assertion on the cache-disabled path shows up.
#
[ -e "$SERVER_RECEIPT" ] || fail "server did not create $SERVER_RECEIPT"
[ -e "$CLIENT_RECEIPT" ] || fail "client did not create $CLIENT_RECEIPT"

for log in "$SERVER_LOG" "$CLIENT_LOG"; do
	#
	#  Both connections must complete.  Caching being off changes what the
	#  handshake stores, not whether the handshake works.
	#
	count=$(grep -c "TLS handshake completed" "$log")
	[ "$count" = "2" ] || fail "expected two completed handshakes in $log, found $count"

	#
	#  Neither connection may resume.  The second connection is the one
	#  which would resume if a session had been stored.
	#
	if grep -q "resumed    : yes" "$log"; then
		fail "a session resumed in $log, so caching was not disabled"
	fi

	count=$(grep -c "resumed    : no" "$log")
	[ "$count" = "2" ] || fail "expected two unresumed sessions in $log, found $count"

	#
	#  None of the cache sections may run.  They are still in the
	#  configuration, so a section which runs anyway is a real fault
	#  rather than a missing section.
	#
	for section in "load session" "store session" "clear session"; do
		if grep -q "^(.*)  *$section {" "$log"; then
			fail "'$section' ran in $log, with caching disabled"
		fi
	done

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
