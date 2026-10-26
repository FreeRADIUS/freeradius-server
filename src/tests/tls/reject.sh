#!/bin/sh
#
#  Run unit_test_tls with -R, so that unit_test_tls rejects the session after
#  the handshake has succeeded, the way policy rejects a session.  Then check
#  that unit_test_tls did not cache the session.
#
#  A caller runs `fr_tls_session_fail_session()` when the caller decides that
#  a session is not worth keeping.  rlm_eap_tls reaches the same function
#  through `eap_tls_fail()` when policy returns reject.
#  `fr_tls_session_fail_session()` runs `fail session { ... }`, and then
#  `fr_tls_ticket_stateful_clear_session()`.  Of the TLS tests, only this test
#  and `fail_resumed.sh` reach `fr_tls_ticket_stateful_clear_session()`.  The
#  other TLS tests either complete the handshake and cache the session, or
#  fail before a session exists.
#
#  `fr_tls_ticket_stateful_clear_session()` runs every queued cache operation
#  before `fr_tls_ticket_stateful_clear_session()` returns.  In a build with
#  assertions enabled, `tls_connection_connected()` checks that no cache
#  operation is left queued.
#
#  This test covers the case where `clear session { ... }` does not run,
#  because no session was loaded.  `fail_resumed.sh` covers the case where
#  `clear session { ... }` does run.
#
#  Because `ticket_stateful.c` sets `SSL_SESS_CACHE_NO_INTERNAL`, OpenSSL holds
#  no session for `SSL_CTX_remove_session()` to find, and OpenSSL never runs the
#  remove callback.  Because of that, `fr_tls_ticket_stateful_clear_session()`
#  queues the clear directly instead of calling `SSL_CTX_remove_session()`.
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
CLIENT_LOG="$OUTPUT/reject_client.log"
RECEIPT="$OUTPUT/reject.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$CLIENT_LOG" "$RECEIPT"

fail() {
	echo "reject.sh: $1"
	echo "--- $LOG ---"
	cat "$LOG"
	echo "--- $CLIENT_LOG ---"
	cat "$CLIENT_LOG"
	exit 1
}

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "reject.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -R \
	-e 'echo | openssl s_client -connect "127.0.0.1:$PORT" \
		-cert "$CERTDIR/client.pem" \
		-key "$CERTDIR/client.key" -pass pass:whatever \
		-CAfile "$CERTDIR/ca.pem" > "$CLIENT_LOG" 2>&1' \
	> "$LOG" 2>&1

#
#  The rejection proves nothing unless the handshake got far enough for
#  OpenSSL to offer a session to cache.
#
grep -q "TLS handshake completed" "$LOG" || \
	fail "the handshake did not complete, no session to reject"

grep -q "Rejecting the session after a successful handshake" "$LOG" || \
	fail "the server did not reject the session, -R had no effect"

#
#  A rejected connection is never a connected one.  The handshake here
#  succeeds and the ticket sections still run, so the connection reaches the
#  same place a working connection reaches.  What tells the two apart is that
#  a failed connection takes the close callback and never the connected one,
#  which is the whole reason the two callbacks are separate.
#
if grep -q "connection state is now connected" "$LOG"; then
	fail "a rejected connection reached the connected state"
fi

if grep -q "Connection is up and can carry application data" "$LOG"; then
	fail "a rejected connection ran the connected callback"
fi

#
#  Because `fr_tls_ticket_stateful_clear_session()` cancels the pending store,
#  the `store session { ... }` section must not run.  If the section runs, the
#  server cached a rejected session.
#
if grep -q "# store session" "$LOG"; then
	fail "store session ran, fr_tls_ticket_stateful_clear_session() did not cancel the store"
fi

#
#  `clear session { ... }` must not run either.  Nothing was loaded from the
#  cache on this connection, the handshake is the first handshake, and
#  `fr_tls_ticket_stateful_clear_session()` cancelled the store.  Because no
#  cache entry exists to remove, `fr_tls_ticket_stateful_clear_session()` does
#  not queue a clear.  Policy would otherwise run against an entry which does
#  not exist.
#
#  The clear runs for a session which was loaded and then failed.
#  `fail_resumed.sh` covers that case.
#
if grep -q "# clear session" "$LOG"; then
	fail "clear session ran, although no session was ever loaded from the cache"
fi

#
#  Any assertion failure fails this test.  The assertion this test can trip is
#  the one which catches a cache operation that `tls_ticket_stateful_drain()` left queued.
#
if grep -q "ASSERT FAILED" "$LOG"; then
	fail "an assertion failed, check whether tls_ticket_stateful_drain() left a cache operation queued"
fi

#
#  `fail session { ... }` reads the request which ran the handshake, through
#  `parent`, because the section itself runs as a subrequest.  This is the
#  test which pins that, rather than alert_recv.sh or alert_send.sh: here
#  unit_test_tls is at both ends, neither end closes the connection abruptly,
#  and the section therefore always runs.
#
#  Until `fail` was added to server_unlang_section in
#  src/lib/server/cf_file.c, `fail session { ... }` could not hold an `if` at
#  all, so these checks also pin that fix.  Reverting the fix stops the
#  configuration parsing, which fails every test in this directory.
#
#  `Error` is set because `load session { ... }` answered `notfound` earlier
#  in this handshake, which is the normal answer on a first connection.  No
#  alert is sent or received here, the handshake succeeds and the session is
#  rejected afterwards, so both alert lists must be empty.  alert_recv.sh and
#  alert_send.sh are where a populated alert list is checked.
#
grep -q "request.Error = ::Load-Session-Not-Found" "$LOG" || \
	fail "the cache miss did not record Load-Session-Not-Found"

grep -A2 "| parent.request.Error" "$LOG" | grep -q -- "--> true" || \
	fail "fail session could not read parent.request.Error"

grep -A2 "| parent.request.Alert" "$LOG" | grep -q -- "--> false" || \
	fail "fail session saw a request.Alert, although no alert was received"

grep -A2 "| parent.reply.Alert" "$LOG" | grep -q -- "--> false" || \
	fail "fail session saw a reply.Alert, although no alert was sent"

touch "$RECEIPT"
exit 0
