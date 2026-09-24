#!/bin/sh
#
#  Run unit_test_tls with -R, so that it rejects the session after the
#  handshake has succeeded, the way policy does.  Then check that the session
#  was not cached.
#
#  This covers fr_tls_cache_deny(), which is what a caller runs when it decides
#  a session is not worth keeping.  rlm_eap_tls does the same thing when policy
#  returns reject.  Before this test nothing exercised that path: the other TLS
#  tests either complete the handshake and cache the session, or fail before a
#  session exists.
#
#  It also covers the cache drain in tls_connection_cache_session(), which runs
#  fr_tls_cache_pending_push() until nothing is left.  A build with assertions
#  enabled checks that nothing was left queued, see
#  tls_connection_application_data().
#
#  It is the only coverage of `clear session { ... }`.  That section used to be
#  unreachable: fr_tls_cache_deny() asked for the clear by calling
#  SSL_CTX_remove_session(), but cache.c sets SSL_SESS_CACHE_NO_INTERNAL, so
#  OpenSSL held no session for that call to find and never ran the remove
#  callback.  fr_tls_cache_deny() now calls tls_cache_delete_request() itself.
#
#  Environment:
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
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
#  The rejection only means anything if the handshake got far enough for
#  OpenSSL to offer a session to cache.
#
grep -q "TLS handshake completed" "$LOG" || \
	fail "the handshake did not complete, so there was no session to reject"

grep -q "Rejecting the session after a successful handshake" "$LOG" || \
	fail "the server did not reject the session, so -R did nothing"

#
#  fr_tls_cache_deny() cancels the pending store, so the `store session`
#  section must not run.  If it does, a rejected session is being cached.
#
if grep -q "# store session" "$LOG"; then
	fail "the rejected session was cached, so fr_tls_cache_deny() did not cancel the store"
fi

#
#  fr_tls_cache_deny() also asks for the session to be cleared, and the cache
#  drain runs the section.  Nothing else in the test suite reaches this.
#
grep -q "# clear session" "$LOG" || \
	fail "the clear session section did not run, so fr_tls_cache_deny() did not request the clear"

#
#  An assertion failure would mean the cache drain left an operation queued.
#
if grep -q "ASSERT FAILED" "$LOG"; then
	fail "an assertion failed, most likely the cache drain left work queued"
fi

touch "$RECEIPT"
exit 0
