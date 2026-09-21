#!/bin/sh
#
#  Run unit_test_tls, connect to it with an OpenSSL client, and check that
#  unit_test_tls wrote its receipt file.
#
#  unit_test_tls writes the receipt file only when it exits successfully, so
#  the presence of that file is the result of the test.  The exit status of
#  the OpenSSL client is ignored, because s_client exits non-zero for an
#  ordinary close as readily as for a real failure, and so says nothing
#  about whether the handshake worked.
#
#  Environment:
#    UNIT_TEST_TLS  command which runs unit_test_tls, possibly several words
#    OUTPUT         directory for the log file and the receipt file
#    CONFDIR        directory holding unit_test_tls.conf
#    CERTDIR        directory holding the client certificate
#    DICT_PATH      dictionary directory
#    PORT           port unit_test_tls listens on
#
#  $Id$
#

LOG="$OUTPUT/unit_test_tls.log"
RECEIPT="$OUTPUT/unit_test_tls.receipt"

mkdir -p "$OUTPUT"
rm -f "$LOG" "$RECEIPT"

if [ ! -r "$CERTDIR/client.pem" ]; then
	echo "unit_test_tls.sh: no client certificate in $CERTDIR, run 'make certs'"
	exit 1
fi

#
#  setsid puts the script into a session of its own, so that signalling the
#  session takes the server and anything the server started.  Not every
#  system has setsid, macOS for one, so fall back to running the server as
#  it is.  The trap below cleans up either way.
#
if command -v setsid > /dev/null 2>&1; then
	SETSID="setsid"
else
	SETSID=""
fi

$SETSID $UNIT_TEST_TLS -d "$CONFDIR" -D "$DICT_PATH" -xx -r "$RECEIPT" > "$LOG" 2>&1 &
SERVER_PID=$!

#
#  Signal the session first, for the setsid case, then the process, for the
#  case where the server is not a session leader.  Either may fail, which is
#  why both are tried and neither is checked.
#
cleanup() {
	kill -TERM "-$SERVER_PID" 2> /dev/null
	kill -TERM "$SERVER_PID" 2> /dev/null
}
trap cleanup EXIT INT TERM

#
#  Wait for the server to open its socket.  The log line is the signal that
#  the socket is up, so the client connects as soon as the server is ready
#  rather than after a guessed delay.  The loop bounds how long we wait for
#  a server which never gets there.
#
if sleep 0.1 2> /dev/null; then
	SNOOZE="sleep 0.1"
	TRIES=100
else
	SNOOZE="sleep 1"
	TRIES=30
fi

while [ "$TRIES" -gt 0 ]; do
	grep -q "Waiting for a connection" "$LOG" 2> /dev/null && break

	#
	#  The server died before it got that far.  Stop waiting, and let the
	#  receipt check below report it.
	#
	kill -0 "$SERVER_PID" 2> /dev/null || break

	TRIES=$((TRIES - 1))
	$SNOOZE
done

echo "--- openssl s_client ---" >> "$LOG"

echo | openssl s_client -connect "127.0.0.1:$PORT" \
	-cert "$CERTDIR/client.pem" \
	-key "$CERTDIR/client.key" -pass pass:whatever \
	-CAfile "$CERTDIR/ca.pem" >> "$LOG" 2>&1

#
#  The server exits once the handshake has finished, one way or the other.
#
wait "$SERVER_PID" 2> /dev/null

if [ ! -e "$RECEIPT" ]; then
	echo "unit_test_tls did not create $RECEIPT"
	echo "--- $LOG ---"
	cat "$LOG"
	exit 1
fi

exit 0
