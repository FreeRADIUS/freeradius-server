#!/bin/sh
#
#  Make the post-handshake timer fire, and check that the timer ends the
#  connection.
#
#  OpenSSL finishing a handshake is not the same as the session finishing.
#  fr_tls_session_is_init_finished() returns true only once a session ticket
#  or the first byte of application data arrives.  Until one of the two
#  arrives, a client cannot tell "the ticket is still coming" from "there was
#  never going to be a ticket".  Nothing in TLS bounds that wait, so the
#  library arms a timer.  post_handshake.sh is the only test which makes that
#  timer fire.
#
#  The test has two pieces:
#
#    - `mode = disabled` in no_ticket.conf, so the server does not issue a
#      session ticket.
#    - -H on the server, so the server does not send application data
#      either, and holds the connection open instead of closing the
#      connection.  A close would end the client's wait, so the timer would
#      never fire.
#
#  The client therefore waits for a session ticket or a byte of application
#  data which never arrives.  The timer fires, and the connection fails.  The
#  client is the end which reports the failure, because the client is the end
#  which waits.
#
#  Neither unit_test_tls process writes a receipt.  The client fails on
#  purpose and the server ends with the client, so the test reads the two log
#  files instead.  The test checks six facts:
#
#    1.  The server completed the handshake.
#    2.  The server reached the connected state.
#    3.  The server held the connection open, so -H took effect.
#    4.  The post-handshake timer fired once on the client.
#    5.  The timer failed the client's connection.
#    6.  The client never reached the connected state.
#
#  The test does not check that the server issued no session ticket.
#  no_ticket.sh covers that check.
#
#  Environment:
#    UNIT_TEST_TLS  command that runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log files and the receipt file
#    CONFDIR        directory holding no_ticket.conf
#    DICT_PATH      dictionary directory
#    PORT           port that unit_test_tls listens on
#
#  The test takes about two seconds.  TLS_POST_HANDSHAKE_TIMEOUT in
#  src/lib/tls/connection.c sets the wait at two seconds.
#
#  $Id$
#

SERVER_LOG="$OUTPUT/post_handshake_server.log"
CLIENT_LOG="$OUTPUT/post_handshake_client.log"
RECEIPT="$OUTPUT/post_handshake.receipt"

mkdir -p "$OUTPUT"
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$RECEIPT"

export CLIENT_LOG

$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_ticket -xx -H \
	-e '$UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -n no_ticket -xx \
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
#  The handshake has to succeed first.  A timer which fires because the
#  handshake never finished would prove nothing.  The server is the end which
#  reports success, because the server is the end which reaches the connected
#  state: the client never does, which is the whole point of the test.
#
grep -q "TLS handshake completed" "$SERVER_LOG" || \
	fail "the handshake did not complete, so the timer proves nothing"

grep -q "connection state is now connected" "$SERVER_LOG" || \
	fail "the server never connected, so the handshake did not finish"

grep -q "Holding the connection open" "$SERVER_LOG" || \
	fail "the server did not hold the connection open, -H had no effect"

#
#  The timer fired, once, and it is the thing which ended the connection.
#
count=$(grep -c "Timed out waiting for data after the handshake" "$CLIENT_LOG")
[ "$count" = "1" ] || \
	fail "expected the post-handshake timer to fire once, it fired $count times"

grep -q "connection failed: tls" "$CLIENT_LOG" || \
	fail "the timer fired but did not fail the connection"

#
#  A connection which reached the connected state was never waiting, so the
#  timer could not have been what ended it.
#
if grep -q "connection state is now connected" "$CLIENT_LOG"; then
	fail "the client connected, so it was not waiting on the post-handshake timer"
fi

#
#  The test writes out the receipt itself, so that if a crash causes an
#  early exit the error is flagged by the make framework.
#
touch "$RECEIPT"
exit 0
