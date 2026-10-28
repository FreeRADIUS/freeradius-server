#!/bin/sh
#
#  Check that the server frees a TLS session without an assertion failure when
#  the cache operations of the session have not run.
#
#  The server queues `store session` when it issues the ticket, and the section
#  needs a request to run.  If the server frees the session before that queued
#  operation runs, the operation cannot run, and the TLS library must discard
#  it rather than assert.
#
#  `unit_test_tls -Q` reaches that state deterministically.  Once the handshake
#  has succeeded and `store session` is queued, before it runs, `-Q` frees the
#  connection.  Freeing it there frees the session with the operation still
#  pending.  This does not depend on when the peer closes, so it behaves the
#  same on every platform.
#
#  `openssl s_client` is only here to complete a handshake with the server; its
#  own close timing no longer matters.
#
#  The test passes when both of these conditions hold:
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

export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n stateful_tls13 -xx -Q \
	-e 'openssl s_client -connect "127.0.0.1:$PORT" -tls1_3 \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/ca.pem" < /dev/null > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

if grep -qE "CAUGHT SIGNAL|ASSERT FAILED" "$LOG"; then
	fail "a signal or a failed assertion appears in $LOG"
fi

#
#  `-Q` only fires once the handshake has finished and `store session` is
#  queued, so this message also proves the handshake got that far.  The
#  'Discarding queued cache operations' message then proves the server
#  discarded that queued operation when it freed the session.
#
grep -q "Aborting the connection with cache operations still queued" "$LOG" || \
	fail "the server did not reach a queued cache operation to abort"
grep -q "Discarding queued cache operations" "$LOG" || \
	fail "the server did not free the session with queued cache operations"

touch "$RECEIPT"
exit 0
