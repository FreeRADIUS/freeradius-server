#!/bin/sh
#
#  Check that the server frees a TLS session without an assertion failure when
#  the cache operations of the session have not run.
#
#  A client can close the connection after the handshake has finished and
#  before `store session` has run.  The server queues `store session` when the
#  server issues the ticket, and the section needs a request to run.  If the
#  server frees the session before `store session` runs, the queued operation
#  cannot run.  The TLS library must then discard the operation.
#
#  Setting `TLS_TEST_STORE_DELAY=yes` makes `store session` call the `delay`
#  module.  `common.conf` defines the `delay` module.  The delay makes
#  `store session` yield for 2 seconds.
#
#  The client is `openssl s_client`, and `openssl s_client` reads its input from
#  `/dev/null`.  Because of that input, `openssl s_client` closes the connection
#  as soon as the handshake has finished.  The server sees the close while
#  `store session` is still yielding.
#
#  The server frees the session when the connection closes.  The test passes
#  when both of these conditions hold:
#    1. The server log says that the server discarded the queued cache
#       operations when freeing the session.
#    2. The server log has no signal and no failed assertion.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding stateful_tls13.conf
#    CERTDIR        directory holding the test certificates
#    DICT_PATH      dictionary directory
#    PORT           port that `unit_test_tls` listens on
#
#  `make test.tls` sets every variable above and runs `abort_pending.sh`.  The
#  recipe is in `src/tests/tls/all.mk`, and the configuration is in
#  `src/tests/tls/stateful_tls13.conf`.
#
#  $Id$
#

LOG="$OUTPUT/abort_pending_server.log"
CLIENT_LOG="$OUTPUT/abort_pending_client.log"
RECEIPT="$OUTPUT/abort_pending.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "abort_pending.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "abort_pending.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG TLS_TEST_STORE_DELAY=yes

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n stateful_tls13 -xx \
	-e 'openssl s_client -connect "127.0.0.1:$PORT" -tls1_3 \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/ca.pem" < /dev/null > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$LOG"; then
	fail "a signal or a failed assertion appears in $LOG"
fi

#
#  The handshake has to finish, or the test closes the connection before the
#  server queues `store session`, and tests nothing.
#
count=$(grep -c "TLS handshake completed" "$LOG")
[ "$count" = "1" ] || fail "expected one completed handshake, found $count"

#
#  The store section has to start before the server frees the session.  The
#  'Discarding queued cache operations' message proves that the server
#  discarded the queued operation when freeing the session.
#
grep -q "# store session\|store session {" "$LOG" || fail "store session did not run"
grep -q "Discarding queued cache operations" "$LOG" || \
	fail "the server did not free the session with queued cache operations"

touch "$RECEIPT"
exit 0
