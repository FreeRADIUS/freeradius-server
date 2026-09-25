#!/bin/sh
#
#  Run unit_test_tls with -R, so that unit_test_tls rejects the session after
#  the handshake has succeeded, the way policy rejects a session.  Then check
#  that unit_test_tls did not cache the session.
#
#  A caller runs fr_tls_cache_clear_session() when the caller decides that a
#  session is not worth keeping.  rlm_eap_tls calls the same function when
#  policy returns reject.  No other TLS test reaches that function.  The other
#  TLS tests either complete the handshake and cache the session, or fail
#  before a session exists.
#
#  fr_tls_cache_clear_session() runs every queued cache operation before
#  fr_tls_cache_clear_session() returns.  In a build with assertions enabled,
#  tls_connection_application_data() and _fr_tls_session_free() both check
#  that no cache operation is left queued.
#
#  This test is the only coverage of the clear session { ... } section.  That
#  section was unreachable while fr_tls_cache_deny() asked for the clear by
#  calling SSL_CTX_remove_session().  cache.c sets SSL_SESS_CACHE_NO_INTERNAL,
#  so OpenSSL holds no session for that call to find, and OpenSSL never runs
#  the remove callback.  fr_tls_cache_deny() now calls
#  tls_cache_delete_request() itself.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  "make test.tls" sets every variable above and runs this script.  The recipe
#  is in src/tests/tls/all.mk.
#
#  $Id$
#

LOG="$OUTPUT/reject.log"
RECEIPT="$OUTPUT/reject.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

fail() {
	echo "reject.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "reject.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -R > "$LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$LOG" 2> /dev/null && break

	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

echo "--- openssl s_client ---" >> "$LOG"

echo | openssl s_client -connect "127.0.0.1:$PORT" \
	-cert "$CERTDIR/client.pem" \
	-key "$CERTDIR/client.key" -pass pass:whatever \
	-CAfile "$CERTDIR/ca.pem" >> "$LOG" 2>&1

wait "$SERVER_PID" 2> /dev/null

#
#  The rejection proves nothing unless the handshake got far enough for
#  OpenSSL to offer a session to cache.
#
grep -q "TLS handshake completed" "$LOG" || \
	fail "the handshake did not complete, no session to reject"

grep -q "Rejecting the session after a successful handshake" "$LOG" || \
	fail "the server did not reject the session, -R had no effect"

#
#  fr_tls_cache_clear_session() cancels the pending store, so the
#  store session { ... } section must not run.  If that section runs, the
#  server cached a rejected session.
#
if grep -q "# store session" "$LOG"; then
	fail "store session ran, fr_tls_cache_clear_session() did not cancel the store"
fi

#
#  fr_tls_cache_clear_session() also requests the clear, and runs the
#  clear session { ... } section itself.  Nothing else in the test suite
#  reaches that section.
#
grep -q "# clear session" "$LOG" || \
	fail "clear session did not run, fr_tls_cache_clear_session() did not request the clear"

#
#  Any assertion failure fails this test.  The assertion this test can trip is
#  the one which catches a cache operation that tls_cache_drain() left queued.
#
if grep -q "ASSERT FAILED" "$LOG"; then
	fail "an assertion failed, check whether tls_cache_drain() left a cache operation queued"
fi

touch "$RECEIPT"
exit 0
